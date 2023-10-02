package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/preset"
)

// TestPresetErrorCodesRegistered 验证预设目录初始化/恢复领域复用根包已登记错误码：
// 缺少/无效预览确认令牌与非法请求映射 REQ_INVALID，预览过期/目录冲突/版本降级/
// 状态冲突映射 CONFLICT，未授权映射 ACCESS_DENIED，应用停用映射 CLIENT_DISABLED，
// 存储不可用映射 DB_UNAVAILABLE，审计失败映射 AUDIT_WRITE_FAILED；不新增注册码。
func TestPresetErrorCodesRegistered(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode preset.ErrorCode
		wantHTTP int
	}{
		{name: "非法请求", err: fmt.Errorf("%w: bad", preset.ErrInvalidRequest), wantCode: preset.CodeReqInvalid, wantHTTP: 400},
		{name: "作用范围无效", err: preset.ErrScopeInvalid, wantCode: preset.CodeReqInvalid, wantHTTP: 400},
		{name: "缺少预览令牌", err: preset.ErrPreviewRequired, wantCode: preset.CodeReqInvalid, wantHTTP: 400},
		{name: "预览已过期", err: preset.ErrPreviewStale, wantCode: preset.CodeConflict, wantHTTP: 409},
		{name: "目录冲突", err: preset.ErrCatalogConflict, wantCode: preset.CodeConflict, wantHTTP: 409},
		{name: "拒绝降级", err: preset.ErrCatalogDowngrade, wantCode: preset.CodeConflict, wantHTTP: 409},
		{name: "状态冲突", err: preset.ErrStateConflict, wantCode: preset.CodeConflict, wantHTTP: 409},
		{name: "未获准操作", err: preset.ErrAccessDenied, wantCode: preset.CodeAccessDenied, wantHTTP: 403},
		{name: "应用已停用", err: preset.ErrApplicationInactive, wantCode: preset.CodeClientDisabled, wantHTTP: 403},
		{name: "存储不可用", err: preset.ErrStoreUnavailable, wantCode: preset.CodeDBUnavailable, wantHTTP: 503},
		{name: "审计不可用", err: preset.ErrAuditUnavailable, wantCode: preset.CodeAuditWriteFailed, wantHTTP: 503},
		{name: "服务选项无效", err: preset.ErrOptionsInvalid, wantCode: preset.CodeInternalError, wantHTTP: 500},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := preset.CodeOf(test.err)
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
	// 未分类内部错误映射为 INTERNAL_ERROR（不进入任何具体错误码）；该码已登记。
	if got := preset.CodeOf(errors.New("unclassified")); got != preset.CodeInternalError {
		t.Fatalf("CodeOf(未分类错误) = %q，期望 INTERNAL_ERROR", got)
	}
}
