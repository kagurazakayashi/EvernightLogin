package serverapp

// 步骤 190：应用逻辑删除的宿主再次认证回调。
//
// 页面与管理 JSON API 的删除入口都必须先经过这里：把“当前请求持有新鲜管理强认证”
// 的短时事实合成策略评估信号，交给真实 reauth/policy 链按 application.delete 的目录
// 默认策略复核（强认证 + 新鲜度 + 显式确认），并把目标应用与行版本绑定进参数摘要。
// 管理事实缺失/过期或策略拒绝一律 fail-closed；本回调只复核认证，应用删除的最终
// 授权/状态机/审计仍由 internal/app 领域服务执行。

import (
	"context"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	ui "github.com/kagurazakayashi/EvernightLogin/ui"
	"strconv"
)

// applicationDeleteOperationID 是应用删除对应的敏感操作目录稳定标识。
const applicationDeleteOperationID = "application.delete"

// applicationDeleteReauth 校验应用逻辑删除前的再次认证。binding 必须与页面/API
// 表单中的实际目标应用与行版本一致；页面确认框不是授权。
func applicationDeleteReauth(ctx context.Context, gate *SecurityGate, userID string,
	binding ui.UIAppDeleteBinding) error {
	if gate == nil || gate.Reauth == nil || gate.Policy == nil {
		return reauth.ErrReauthRequired
	}
	if !account.ValidUserID(userID) {
		return reauth.ErrAccessDenied
	}
	if !app.ValidApplicationID(binding.ApplicationID) || binding.ExpectedRowVersion <= 0 {
		return reauth.ErrInvalidRequest
	}
	fact, ok := gate.takeManagementFact(userID)
	if !ok || fact.verifiedAt.IsZero() {
		return reauth.ErrReauthRequired
	}
	caller, err := reauth.UserCaller(userID)
	if err != nil {
		return reauth.ErrAccessDenied
	}
	safeRequestID := ""
	if account.ValidateRequestID(binding.RequestID) == nil {
		safeRequestID = binding.RequestID
	}
	request := reauth.Request{
		ScopeID: "system", OperationID: applicationDeleteOperationID,
		TargetType: "application", TargetID: binding.ApplicationID,
		Params: map[string]string{
			"application_id":       binding.ApplicationID,
			"expected_row_version": strconv.FormatInt(binding.ExpectedRowVersion, 10),
			"request_id":           safeRequestID,
		},
		Description: "删除应用（逻辑删除）",
		RequestID:   safeRequestID,
	}
	// 显式确认由页面复选框/管理 API 请求体在调用本回调前校验；策略仍会按目录默认
	// 要求复核认证强度与新鲜度，确认不能替代认证。
	signals := reauth.Signals{VerifiedAt: fact.verifiedAt, Strength: policy.StrengthStrong,
		Complete: true, Confirmed: true}
	approved, err := gate.Reauth.Authorize(reauth.WithSignals(ctx, signals), caller, request)
	if err != nil {
		return err
	}
	if notifyErr := gate.Reauth.NotifyOutcome(ctx, approved, reauth.OutcomeSuccess); notifyErr != nil {
		_ = notifyErr
	}
	return nil
}
