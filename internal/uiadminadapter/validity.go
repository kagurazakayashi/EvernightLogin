package uiadminadapter

// 步骤 235：管理页账户有效期读写适配器。
//
// 页面与 234 管理 API 使用同一授权（users.read/users.update）与同一账户领域
// 服务（root 保护、UTC 半开区间、行版本冲突、关键审计）。本文件只负责页面请求
// 的字段复核、页面“变更理由”审计投影与视图转换；不复制领域规则。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// GetUserValidity 读取目标用户有效期与当前可用性（users.read）。
func (a *Adapter) GetUserValidity(ctx context.Context, adminUserID,
	userID string) (login.UIAdminUserValidityView, error) {
	if err := a.check(ctx, adminUserID, "users.read"); err != nil {
		return login.UIAdminUserValidityView{}, err
	}
	if !account.ValidUserID(userID) {
		return login.UIAdminUserValidityView{}, adminErr("REQ_INVALID")
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return login.UIAdminUserValidityView{}, adminErr("ACCESS_DENIED")
	}
	validity, err := a.opts.Account.GetUserValidity(ctx, caller, userID)
	if err != nil {
		return login.UIAdminUserValidityView{}, mapAccountError(err)
	}
	return toValidityView(validity), nil
}

// SetUserValidity 设置/续期/清除目标用户全局有效期（users.update）。
//
// 页面要求变更理由：在调用领域服务前写入独立的“变更意图”审计（真实操作者、
// 理由、UTC 时间与请求编号），审计失败时不发起变更。领域服务随后在关键审计
// 事务中记录操作者/请求编号与实际字段变化；root 由领域服务拒绝。
func (a *Adapter) SetUserValidity(ctx context.Context, adminUserID, userID string,
	change login.UIAdminUserValidityChange) (login.UIAdminUserValidityView, error) {
	if err := a.check(ctx, adminUserID, "users.update"); err != nil {
		return login.UIAdminUserValidityView{}, err
	}
	if !account.ValidUserID(userID) {
		return login.UIAdminUserValidityView{}, adminErr("REQ_INVALID")
	}
	reason := strings.TrimSpace(change.Reason)
	if reason == "" || len(reason) > 200 {
		return login.UIAdminUserValidityView{}, adminErr("REQ_INVALID")
	}
	if change.ValidFrom != nil && change.ValidUntil != nil &&
		!change.ValidUntil.After(*change.ValidFrom) {
		return login.UIAdminUserValidityView{}, adminErr("REQ_INVALID")
	}
	caller, err := account.UserCaller(adminUserID)
	if err != nil {
		return login.UIAdminUserValidityView{}, adminErr("ACCESS_DENIED")
	}
	requestID := strings.TrimSpace(change.RequestID)
	if requestID != "" {
		caller, err = caller.WithRequestID(requestID)
		if err != nil {
			return login.UIAdminUserValidityView{}, adminErr("REQ_INVALID")
		}
	}
	if a.opts.Audit != nil {
		event := audit.Event{
			Actor:   audit.Actor{Type: audit.ActorUser, ID: adminUserID},
			Action:  "user.validity.set.requested",
			Target:  audit.Target{Type: "user", ID: userID},
			Outcome: audit.OutcomeSuccess, RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "reason", After: reason},
				{Field: "valid_from", After: formatValidityAuditTime(change.ValidFrom)},
				{Field: "valid_until", After: formatValidityAuditTime(change.ValidUntil)},
				{Field: "expected_row_version", After: formatInt64(change.ExpectedRowVersion)},
			},
		}
		if err := a.opts.Audit.Record(ctx, event); err != nil {
			return login.UIAdminUserValidityView{}, adminErr("AUDIT_WRITE_FAILED")
		}
	}
	result, err := a.opts.Account.SetValidity(ctx, caller,
		account.ValidityCommandRequest{UserID: userID,
			ExpectedRowVersion: change.ExpectedRowVersion,
			ValidFrom:          change.ValidFrom, ValidUntil: change.ValidUntil})
	if err != nil {
		return login.UIAdminUserValidityView{}, mapAccountError(err)
	}
	// 领域服务返回 User 快照不含 root 标记；重新读取一次以拿到精确可用性/root。
	validity, err := a.opts.Account.GetUserValidity(ctx, caller, result.User.ID)
	if err != nil {
		return login.UIAdminUserValidityView{}, mapAccountError(err)
	}
	return toValidityView(validity), nil
}

// toValidityView 投影页面有效期视图（不包含秘密或个人资料）。
func toValidityView(validity account.UserValidity) login.UIAdminUserValidityView {
	return login.UIAdminUserValidityView{UserID: validity.UserID,
		Status: string(validity.Status), IsRoot: validity.IsRoot,
		ValidFrom: validity.ValidFrom, ValidUntil: validity.ValidUntil,
		RowVersion: validity.RowVersion, Available: validity.Available,
		Reason: string(validity.Reason), CheckedAt: validity.CheckedAt}
}

// formatValidityAuditTime 把可选 UTC 时间渲染为审计差异值（空表示清除）。
func formatValidityAuditTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// formatInt64 把行版本等整数渲染为审计差异值。
func formatInt64(value int64) string {
	return fmt.Sprintf("%d", value)
}
