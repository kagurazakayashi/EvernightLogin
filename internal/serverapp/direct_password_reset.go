package serverapp

// 步骤 257：直接重置他人密码的“同事务附带效果”编排。
//
// 直接管理重置在写入新密码/历史/安全版本（internal/authn）之外，还必须在**同一审计
// 事务**内完成：
//   - 作废该用户所有 pending 找回入口，并撤销其一次性凭证（旧找回链接立即失效）；
//   - 写入 OAuth 撤销可靠事件（outbox，供后续消费者撤销外部令牌），与关键审计一致提交。
//
// 旧会话不需要在事务内逐行撤销：安全版本已在同一事务内递增，会话/刷新令牌校验都会
// 比对当前 security_version，旧凭证立即失效；提交后再 best-effort 调会话服务清理
// 活动会话行（失败不回滚已成功的密码重置，安全版本已保证失效），与本项目既有改密/
// 找回路径语义一致。
//
// 本文件只新增编排能力，复用既有 passwordreset/credential/session 真实实现；不保存
// 密码、哈希、令牌明文，也不把 system-caller 找回入口暴露成无授权捷径——调用方必须
// 已完成专门权限与操作绑定两步验证证明的校验，并在同一事务内先消费证明。

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/passwordreset"
	passwordresetsqlite "github.com/kagurazakayashi/EvernightLogin/internal/passwordreset/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// passwordResetCredentialPurpose 是找回入口一次性凭证的固定用途（与
// internal/passwordreset 内部常量一致；本包只用于撤销旧入口凭证，不签发新凭证）。
const passwordResetCredentialPurpose = "password.reset"

// passwordChangedOutboxReason 是密码变更 OAuth 撤销事件原因（与既有改密/找回一致）。
const passwordChangedOutboxReason = "password_changed"

// DirectResetLinkInvalidation 是事务内旧找回入口失效与撤销事件的结果。
type DirectResetLinkInvalidation struct {
	CancelledRequests  int64
	RevokedCredentials int64
	OutboxEventID      string
}

// DirectPasswordResetEffects 是直接重置密码的事务内/提交后附带效果执行器。
type DirectPasswordResetEffects struct {
	passwordResets *passwordresetsqlite.Store
	credentials    *credential.Service
	sessions       *session.Service
	now            func() time.Time
}

// NewDirectPasswordResetEffects 从共享装配构造附带效果执行器；缺少存储/审计事务能力时
// 返回错误（调用方 fail-closed，不降级为事务外补做）。
func NewDirectPasswordResetEffects(base *Base) (*DirectPasswordResetEffects, error) {
	if base == nil || base.Store == nil {
		return nil, errors.New("直接重置附带效果缺少数据库存储")
	}
	resets, err := passwordresetsqlite.New(base.Store)
	if err != nil {
		return nil, fmt.Errorf("构造找回入口存储失败: %w", err)
	}
	effects := &DirectPasswordResetEffects{passwordResets: resets, now: base.Now}
	if effects.now == nil {
		effects.now = time.Now
	}
	if base.Services != nil {
		effects.credentials = base.Services.Credential
		effects.sessions = base.Services.Sessions
	}
	return effects, nil
}

// InvalidatePriorResetLinksTx 在调用方审计事务内作废目标用户的 pending 找回入口、
// 撤销其一次性凭证并写入 OAuth 撤销 outbox：
//   - 任一存储步骤失败整体返回错误（调用方回滚，密码未改、证明未消费）；
//   - 凭证撤销是条件更新，已消费/过期/不存在视为已失效（不计入 revoke 数），不是错误；
//   - 不发送邮件、不修改用户资料、不记录 token/链接。
func (e *DirectPasswordResetEffects) InvalidatePriorResetLinksTx(ctx context.Context,
	tx audit.Tx, userID, requestID string) (DirectResetLinkInvalidation, error) {
	result := DirectResetLinkInvalidation{}
	if tx == nil || e == nil || e.passwordResets == nil {
		return result, fmt.Errorf("%w: 直接重置附带效果未装配", passwordreset.ErrOptionsInvalid)
	}
	pending, err := e.passwordResets.ListPendingTx(ctx, tx, userID)
	if err != nil {
		return result, err
	}
	cancelled, err := e.passwordResets.CancelPendingTx(ctx, tx, userID, e.now().UTC())
	if err != nil {
		return result, err
	}
	result.CancelledRequests = cancelled
	if len(pending) > 0 {
		if e.credentials == nil {
			return result, errors.New("撤销旧找回凭证所需的凭证服务未装配")
		}
		for _, request := range pending {
			if request.CredentialID == "" {
				continue
			}
			revoked, revokeErr := e.credentials.CancelTx(ctx, tx, credential.CancelRequest{
				ID: request.CredentialID, Purpose: passwordResetCredentialPurpose,
				Target: userID,
			})
			if revokeErr != nil {
				return result, revokeErr
			}
			if revoked {
				result.RevokedCredentials++
			}
		}
	}
	outboxID, err := e.passwordResets.InsertOutboxTx(ctx, tx, userID,
		passwordChangedOutboxReason, e.now().UTC())
	if err != nil {
		return result, err
	}
	result.OutboxEventID = outboxID
	_ = requestID
	return result, nil
}

// RevokeSessionsAfterCommit 在密码/安全版本提交成功后 best-effort 撤销目标全部活动会话
// （安全版本已保证旧会话失效；本步只做服务端清理与审计）。失败由调用方记录失败审计，
// 不回滚已成功的密码重置。
func (e *DirectPasswordResetEffects) RevokeSessionsAfterCommit(ctx context.Context,
	userID string) (int64, error) {
	if e == nil || e.sessions == nil {
		return 0, errors.New("会话服务未装配")
	}
	return e.sessions.RevokeAllForUser(ctx, userID, "password_direct_reset")
}
