package app

// 步骤 256：直接修改他人用户名的公开 Go 门面（管理员直接管理能力）。
//
// 与本人受控更名（Profile.ChangeUsername）是两条不同能力：
//   - 本人更名要求本人近期再次验证、受本人改名冷却限制；
//   - 本门面要求操作者持有独立系统权限 users.username.change.other，并出示本次操作绑定
//     的两步验证证明（步骤 255 的目标绑定一次性证明），不需要目标当前密码、目标确认或
//     另一管理员审批。
//
// 安全链路（任一环节不满足都整体拒绝，不产生半更新）：
//  1. 可信身份：只接受真实用户管理会话（AdminSession）；本机受信操作者没有用户两步因素，
//     不能用于直接管理操作。执行的目标/行版本/理由来自可信会话调用。
//  2. 授权：真实 authz 内核判定操作者在系统范围仍持有 users.username.change.other；
//     目标必须存在、非 root、处于稳定状态（active/disabled），行版本与操作者看到的一致。
//  3. 证明：用步骤 255 的契约核对证明令牌绑定——操作者、会话、操作、目标用户、参数与
//     “本次新用户名 display 串”。证明绑定的 display 串由本门面从操作者提交输入按既有
//     Unicode 规则规范化后得到，且**写入的用户名就是该 display 串**（唯一性/保留名用其
//     规范化键判定）；换目标/换新用户名/换会话/证明重放均拒绝。
//  4. 一致提交：证明消费、唯一性与行版本条件更新、关键审计在**同一审计事务**内完成；
//     提交失败整体回滚（证明不烧毁、可重新准备后重试），成功后重放不再二次执行。
//  5. 频率限制：进程内有界窗口（操作者+目标，默认 5 次/分）只用于防滥用，不是授权依据，
//     多进程/多实例不共享；授权仍只由 authz 判定。
//  6. 告知：成功后 best-effort 向目标最近已验证邮箱入队安全告知（不含密码/令牌等秘密），
//     失败不回滚已成功的更名，也不宣称已送达。
//
// 页面/CLI 入口由后续步骤单独接通；本文件不签发会话、不修改邮箱/MFA/角色，也不处理 root
// 目标（root 用户名只走本人受控流程或本地应急流程）。

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
	"github.com/kagurazakayashi/EvernightLogin/internal/profile"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
	"github.com/kagurazakayashi/EvernightLogin/internal/serverapp"
)

const (
	// directUsernamePermissionKey 是直接修改他人用户名的独立权限键（步骤 254 注册表）。
	directUsernamePermissionKey = "users.username.change.other"
	// directRenameLimit 是进程内防滥用窗口上限（非授权依据）。
	directRenameLimit = 5
	// directRenameWindow 是防滥用窗口。
	directRenameWindow = time.Minute
	// maxDirectReasonRunes 是直接管理理由的最大字符数。
	maxDirectReasonRunes = 256
)

// AdminChangeUserUsernameRequest 是 Admin.ChangeUserUsername 的请求。
type AdminChangeUserUsernameRequest struct {
	// Caller 必须是真实用户管理会话（AdminSession）；LocalAdmin 拒绝。
	Caller AdminCaller
	// TargetUserID 是被管理的目标用户稳定 ID（不能是操作者本人，也不能是 root）。
	TargetUserID string
	// NewUsername 是操作者本次提交的新用户名输入；按既有 Unicode 规则规范化后绑定并写入。
	NewUsername string
	// ExpectedRowVersion 是操作者确认的目标资料行版本（乐观并发）。
	ExpectedRowVersion int64
	// Reason 是本次直接管理的理由（写入关键审计；长度受限、去控制字符）。
	Reason string
	// ProofToken 是步骤 255 目标绑定操作证明（一次性，短时有效）。
	ProofToken string
	// RequestID 用于关联调用、领域审计与稳定错误；空值统一生成。
	RequestID string
}

// DirectUserManagementService 是管理员直接管理他人账户的公开门面（当前提供直接改名；
// 直接重置口令由步骤 257 在同一证明能力上实现）。
type DirectUserManagementService interface {
	// ChangeUserUsername 凭独立权限 + 本次两步验证证明直接修改目标用户全局用户名。
	// 稳定用户 ID、角色、应用成员与历史关联保持不变；成功后按策略发送敏感操作告知。
	ChangeUserUsername(ctx context.Context, request AdminChangeUserUsernameRequest) (AdminUserProfile, error)
}

// DirectUserManagement 返回管理员直接管理门面；Runtime 未装配依赖时调用返回明确配置
// 错误，不会静默跳过权限或两步验证。
func (r *Runtime) DirectUserManagement() DirectUserManagementService {
	return &directUserManagementFacade{r: r}
}

type directUserManagementFacade struct{ r *Runtime }

// directRenameLimiter 是进程内有界滑动窗口限流器（防滥用辅助，不是授权依据）。
type directRenameLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
	limit   int
	window  time.Duration
}

func newDirectRenameLimiter(limit int, window time.Duration) *directRenameLimiter {
	return &directRenameLimiter{entries: make(map[string][]time.Time), limit: limit, window: window}
}

func (l *directRenameLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.limit <= 0 || key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	kept := l.entries[key]
	retained := kept[:0]
	for _, timestamp := range kept {
		if timestamp.After(cutoff) {
			retained = append(retained, timestamp)
		}
	}
	if len(retained) >= l.limit {
		l.entries[key] = retained
		return false
	}
	l.entries[key] = append(retained, now)
	if len(l.entries) > 10000 {
		for candidate, timestamps := range l.entries {
			if len(timestamps) == 0 || !timestamps[len(timestamps)-1].After(cutoff) {
				delete(l.entries, candidate)
			}
		}
	}
	return true
}

// directRenameRateLimiter 是进程级共享实例（多实例不共享，文档已说明）。
var directRenameRateLimiter = newDirectRenameLimiter(directRenameLimit, directRenameWindow)

// directManagementErrorCode 把证明/资料领域错误投影为既有公开错误码；未知错误按内部
// 错误处理（不把内部细节透出）。必须先判定错误归属：两个领域的 CodeOf 对未知错误都会
// 回退为 INTERNAL_ERROR，不能靠“返回非空”区分领域。
func directManagementErrorCode(err error) string {
	profileSentinels := []error{
		profile.ErrOptionsInvalid, profile.ErrInvalidRequest, profile.ErrAccessDenied,
		profile.ErrUserNotFound, profile.ErrVersionConflict, profile.ErrUsernameTaken,
		profile.ErrRenameTooSoon, profile.ErrRenameReauthRequired, profile.ErrPhoneInvalid,
		profile.ErrStoreUnavailable, profile.ErrAuditUnavailable, profile.ErrTargetNotManageable,
	}
	for _, sentinel := range profileSentinels {
		if errors.Is(err, sentinel) {
			return string(profile.CodeOf(err))
		}
	}
	reauthSentinels := []error{
		reauth.ErrOptionsInvalid, reauth.ErrInvalidRequest, reauth.ErrAccessDenied,
		reauth.ErrAuthenticationFailed, reauth.ErrReauthRequired, reauth.ErrChallengeInvalid,
		reauth.ErrChallengeExpired, reauth.ErrAttemptsExceeded, reauth.ErrApprovalInvalid,
		reauth.ErrApprovalExpired, reauth.ErrApprovalConsumed, reauth.ErrIntentInvalid,
		reauth.ErrProofBindingMismatch, reauth.ErrSessionMismatch, reauth.ErrProofExpired,
		reauth.ErrMFARequired, reauth.ErrRateLimited, reauth.ErrPolicyUnavailable,
		reauth.ErrStoreUnavailable, reauth.ErrAuditUnavailable, reauth.ErrNotificationFailed,
	}
	for _, sentinel := range reauthSentinels {
		if errors.Is(err, sentinel) {
			return string(reauth.CodeOf(err))
		}
	}
	return string(login.CodeInternalError)
}

// sanitizeDirectReason 去除控制字符并限长；空理由由调用方拒绝。
func sanitizeDirectReason(reason string) string {
	reason = strings.TrimSpace(reason)
	var builder strings.Builder
	count := 0
	for _, character := range reason {
		if count >= maxDirectReasonRunes {
			break
		}
		if unicode.IsControl(character) {
			builder.WriteRune(' ')
			count++
			continue
		}
		builder.WriteRune(character)
		count++
	}
	return strings.TrimSpace(builder.String())
}

// directManagementIdentity 解析可信操作者身份与会话 ID；只接受真实用户完整管理会话。
func (f *directUserManagementFacade) directManagementIdentity(ctx context.Context,
	caller AdminCaller, requestID string) (operatorID, sessionID string, err error) {
	r := f.r
	services := r.coreServices()
	if services == nil || services.Sessions == nil {
		return "", "", configError("服务未装配", requestID)
	}
	if caller.local {
		return "", "", mapDomainError("直接管理操作必须由真实用户管理会话发起",
			string(login.CodeAccessDenied), requestID)
	}
	identity, resolveErr := r.resolveAdmin(ctx, caller, requestID)
	if resolveErr != nil {
		return "", "", resolveErr
	}
	if identity.userID == "" || len(identity.sessionSecret) == 0 {
		return "", "", mapDomainError("管理会话无效",
			string(login.CodeAccessDenied), requestID)
	}
	record, validateErr := services.Sessions.Validate(ctx, string(identity.sessionSecret))
	if validateErr != nil || !record.IsNormal() || record.UserID != identity.userID {
		return "", "", mapDomainError("管理会话无效或不是完整会话",
			string(login.CodeAccessDenied), requestID)
	}
	return identity.userID, record.ID, nil
}

// ChangeUserUsername 实现直接改名（详见类型注释与文件头安全链路）。
func (f *directUserManagementFacade) ChangeUserUsername(ctx context.Context,
	request AdminChangeUserUsernameRequest) (AdminUserProfile, error) {
	r := f.r
	requestID, err := resolveRequestID(ctx, request.RequestID)
	if err != nil {
		return AdminUserProfile{}, err
	}
	managed := r.managedServices()
	if managed == nil || managed.Profile == nil || managed.Checker == nil {
		return AdminUserProfile{}, configError("直接管理依赖未装配", requestID)
	}
	gate := r.securityGate()
	if gate == nil || gate.Reauth == nil {
		return AdminUserProfile{}, configError("敏感操作闸门未装配", requestID)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return AdminUserProfile{}, mapDomainError("目标用户标识无效",
			string(login.CodeReqInvalid), requestID)
	}
	if request.ExpectedRowVersion < 1 {
		return AdminUserProfile{}, mapDomainError("目标资料版本无效",
			string(login.CodeReqInvalid), requestID)
	}
	if strings.TrimSpace(request.NewUsername) == "" {
		return AdminUserProfile{}, mapDomainError("新用户名不能为空",
			string(login.CodeReqInvalid), requestID)
	}
	reason := sanitizeDirectReason(request.Reason)
	if reason == "" {
		return AdminUserProfile{}, mapDomainError("直接管理操作必须填写理由",
			string(login.CodeReqInvalid), requestID)
	}
	if strings.TrimSpace(request.ProofToken) == "" {
		return AdminUserProfile{}, mapDomainError("缺少本次操作的两步验证证明",
			string(login.CodeTokenInvalid), requestID)
	}
	operatorID, sessionID, err := f.directManagementIdentity(ctx, request.Caller, requestID)
	if err != nil {
		return AdminUserProfile{}, err
	}
	if request.TargetUserID == operatorID {
		return AdminUserProfile{}, mapDomainError("本人改名请使用本人受控改名流程",
			string(login.CodeReqInvalid), requestID)
	}
	// 防滥用频率限制（非授权依据）：同一操作者对同一目标的最大尝试次数。
	if !directRenameRateLimiter.allow(operatorID+"|"+request.TargetUserID, r.runtimeNow()) {
		return AdminUserProfile{}, mapDomainError("直接改名请求过于频繁",
			string(login.CodeRateLimited), requestID)
	}
	// 授权：真实 authz 内核判定系统范围独立权限。
	authzCaller, callerErr := authz.UserCaller(operatorID)
	if callerErr != nil {
		return AdminUserProfile{}, configError("构造授权调用者失败", requestID)
	}
	decision, checkErr := managed.Checker.Check(ctx, authzCaller, authz.CheckRequest{
		SubjectUserID: operatorID, ScopeID: "system",
		Permissions: []string{directUsernamePermissionKey}, Mode: authz.ModeAll,
	})
	if checkErr != nil {
		return AdminUserProfile{}, mapDomainError("权限判定不可用",
			"AUTHZ_UNAVAILABLE", requestID)
	}
	if !decision.Allowed {
		return AdminUserProfile{}, mapDomainError("未授予直接修改他人用户名的权限",
			string(login.CodeAccessDenied), requestID)
	}
	// 领域校验：目标存在/非 root/状态稳定/行版本一致/用户名合法（含保留名与同名判断）。
	plan, planErr := managed.Profile.PrepareManagementRename(ctx,
		profile.ManagementRenameRequest{
			OperatorUserID: operatorID, TargetUserID: request.TargetUserID,
			NewUsername: request.NewUsername, ExpectedRowVersion: request.ExpectedRowVersion,
			RequestID: requestID,
		})
	if planErr != nil {
		if replaced, ok := notFoundWhen(planErr, profile.ErrUserNotFound, "user", requestID); ok {
			return AdminUserProfile{}, replaced
		}
		return AdminUserProfile{}, mapDomainError("直接改名校验失败",
			directManagementErrorCode(planErr), requestID)
	}
	// 证明核对：绑定操作者/会话/操作/目标/新用户名 display 串；换目标或换新值都会拒绝。
	reauthCaller, reauthErr := reauth.UserCaller(operatorID)
	if reauthErr != nil {
		return AdminUserProfile{}, configError("构造再次认证调用者失败", requestID)
	}
	prepared, prepareErr := gate.Reauth.PrepareProof(ctx, reauthCaller,
		reauth.ConsumeProofRequest{
			ProofToken: request.ProofToken, ScopeID: "system",
			OperationID: policy.OperationDirectUsernameChange, TargetType: "user",
			TargetID:  request.TargetUserID,
			SessionID: sessionID,
			Intent: &reauth.Intent{Kind: reauth.IntentUsername,
				Username: plan.DisplayUsername},
			RequestID: requestID,
		})
	if prepareErr != nil {
		return AdminUserProfile{}, mapDomainError("直接改名两步验证证明无效或已失效",
			directManagementErrorCode(prepareErr), requestID)
	}
	// 关键提交：证明消费 + 条件更名 + 关键审计同一事务。
	var updated profile.UserProfile
	var approvalID string
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: operatorID},
			Action:    "admin.direct_username_change",
			Target:    audit.Target{Type: "user", ID: request.TargetUserID},
			RequestID: requestID,
			Changes: []audit.FieldChange{
				{Field: "username", Before: plan.BeforeUsername, After: plan.DisplayUsername},
				{Field: "reason", After: reason},
				{Field: "expected_row_version",
					After: strconv.FormatInt(request.ExpectedRowVersion, 10)},
				{Field: "permission", After: directUsernamePermissionKey},
			},
		},
		FailureReasonCode: "admin.direct_username_change_failed",
		FailureErrorCodeFor: func(err error) string {
			return directManagementErrorCode(err)
		},
	}
	err = r.base.Audit.ExecuteCritical(ctx, critical,
		func(txCtx context.Context, tx audit.Tx) error {
			consumed, consumeErr := gate.Reauth.ConsumePreparedProofTx(txCtx, tx,
				reauthCaller, prepared)
			if consumeErr != nil {
				return consumeErr
			}
			approvalID = consumed.ApprovalID
			renamed, renameErr := managed.Profile.ApplyManagementRenameTx(txCtx, tx, plan)
			if renameErr != nil {
				return renameErr
			}
			updated = renamed
			return nil
		})
	if err != nil {
		return AdminUserProfile{}, mapDomainError("直接修改用户名失败",
			directManagementErrorCode(err), requestID)
	}
	// 成功后 best-effort 敏感操作告知：失败不回滚已完成的更名，也不宣称已送达。
	f.notifyDirectUsernameChange(ctx, requestID, approvalID, request.TargetUserID)
	return adminUserProfile(updated), nil
}

// notifyDirectUsernameChange 入队安全告知（去重键由证明批准 ID 派生）；失败只记录
// 可诊断日志/失败审计，不影响已成功业务。
func (f *directUserManagementFacade) notifyDirectUsernameChange(ctx context.Context,
	requestID, approvalID, targetUserID string) {
	r := f.r
	notifier, err := serverapp.NewDirectManagementNotifier(r.base.Deps)
	if err != nil || notifier == nil {
		r.logger.Warn("直接改名安全告知未装配", "error", err)
		return
	}
	dedupKey := "admin-direct-username-change:" + approvalID
	receipt, notifyErr := notifier.Notify(ctx, serverapp.DirectManagementNotice{
		TargetUserID: targetUserID, OperationLabel: "管理员修改了你的用户名",
		OccurredAt: r.runtimeNow(), DedupKey: dedupKey, RequestID: requestID,
	})
	if notifyErr != nil {
		r.logger.Warn("直接改名安全告知未完成",
			"state", receipt.State, "error", notifyErr)
		// 失败审计同样 best-effort（不影响已成功业务）；不含秘密，失败也只记录日志。
		if auditErr := r.base.Audit.RecordFailure(ctx, audit.Event{
			Actor:   audit.Actor{Type: audit.ActorSystem, ID: "direct-user-management"},
			Action:  "admin.direct_username_change_notify_failed",
			Target:  audit.Target{Type: "user", ID: targetUserID},
			Outcome: audit.OutcomeFailure, ErrorCode: "MAIL_DELIVERY_FAILED",
			RequestID: requestID,
			Changes:   []audit.FieldChange{{Field: "state", After: receipt.State}},
		}); auditErr != nil {
			r.logger.Warn("直接改名告知失败审计写入失败", "error", auditErr)
		}
		return
	}
	r.logger.Info("直接改名安全告知已入可靠投递队列",
		"delivery_id", receipt.DeliveryID, "duplicate", receipt.Duplicate)
}
