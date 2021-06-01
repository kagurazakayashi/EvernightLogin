package onboarding

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	"github.com/kagurazakayashi/EvernightLogin/internal/credential"
	"github.com/kagurazakayashi/EvernightLogin/internal/delegation"
)

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// InviteAuthorizer 判定调用者能否创建邀请（生产由 internal/authz 装配）。
// nil 时只有受信 system/local_admin 通道可创建，普通用户 fail-closed。
type InviteAuthorizer interface {
	AuthorizeInvite(ctx context.Context, caller Caller, request CreateRequest) error
}

// ManagementAuthorizer 判定调用者是否具备管理访问（应由强认证会话实现）。
// nil 时只有受信 system/local_admin 通道可审核，普通用户 fail-closed。
type ManagementAuthorizer interface {
	AuthorizeManagement(ctx context.Context, caller Caller) error
}

// ManagementAuthorizerFunc 是管理强认证契约的函数适配器（测试或宿主装配）。
type ManagementAuthorizerFunc func(ctx context.Context, caller Caller) error

// AuthorizeManagement 实现 ManagementAuthorizer。
func (f ManagementAuthorizerFunc) AuthorizeManagement(ctx context.Context, caller Caller) error {
	if f == nil {
		return ErrManagementAuthRequired
	}
	return f(ctx, caller)
}

// InviteAuthorizerFunc 是邀请创建授权的函数适配器。
type InviteAuthorizerFunc func(ctx context.Context, caller Caller, request CreateRequest) error

// AuthorizeInvite 实现 InviteAuthorizer。
func (f InviteAuthorizerFunc) AuthorizeInvite(ctx context.Context, caller Caller, request CreateRequest) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, request)
}

// Options 是构造入驻服务的显式依赖。
type Options struct {
	Store       Store
	Audit       AuditRecorder
	Guard       delegation.Guard
	Credentials *credential.Service
	// InviteAuthorizer 判定创建邀请的权限；nil 时普通用户被拒绝。
	InviteAuthorizer InviteAuthorizer
	// ManagementAuth 判定注册审核的管理强认证；nil 时普通用户被拒绝。
	ManagementAuth ManagementAuthorizer
	// Mailer 是通知邮件发送接口；nil 表示不发送邮件（通知状态记录为 failed）。
	Mailer EmailSender
	// AcceptanceURLBase 是邀请接受入口基础地址（Mailer 非空时必填）。
	AcceptanceURLBase string
	// SupportURL 是审核通知邮件中的支持入口（Mailer 非空时必填）。
	SupportURL string
	// AppName 是邮件模板中的服务名称。
	AppName string
	// PasswordPolicy/HashParams 用于由邀请创建新账户。
	PasswordPolicy authn.PasswordPolicy
	HashParams     authn.Params
	// InvitationTTL 是邀请默认有效期；0 使用 DefaultInvitationTTL。
	InvitationTTL time.Duration
	Now           func() time.Time
	Random        io.Reader
	Logger        *slog.Logger
}

// Service 是入驻领域服务（邀请 + 注册审核）。构造后不可变，不启动协程、不发会话。
type Service struct {
	opts Options
}

// New 校验依赖并构造服务；缺少 Store/Audit/Guard/Credentials 时 fail-closed。
func New(options Options) (*Service, error) {
	if isNil(options.Store) {
		return nil, fmt.Errorf("%w: 入驻存储为空", ErrOptionsInvalid)
	}
	if isNil(options.Audit) {
		return nil, fmt.Errorf("%w: 安全审计写入器为空", ErrOptionsInvalid)
	}
	if isNil(options.Guard) {
		return nil, fmt.Errorf("%w: 委派检查器为空", ErrOptionsInvalid)
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("%w: 一次性凭证服务为空", ErrOptionsInvalid)
	}
	if options.Mailer != nil {
		if problem := acceptanceURLProblem(options.AcceptanceURLBase); problem != "" {
			return nil, fmt.Errorf("%w: %s", ErrOptionsInvalid, problem)
		}
		if problem := acceptanceURLProblem(options.SupportURL); problem != "" {
			return nil, fmt.Errorf("%w: 支持入口地址: %s", ErrOptionsInvalid, problem)
		}
	}
	if options.PasswordPolicy.MinRunes == 0 && options.PasswordPolicy.MaxRunes == 0 &&
		options.PasswordPolicy.HistoryLimit == 0 && len(options.PasswordPolicy.WeakExtraWords) == 0 {
		options.PasswordPolicy = authn.DefaultPasswordPolicy()
	}
	if err := options.PasswordPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	if options.HashParams == (authn.Params{}) {
		options.HashParams = authn.DefaultParams()
	}
	if err := options.HashParams.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOptionsInvalid, err)
	}
	if options.InvitationTTL == 0 {
		options.InvitationTTL = DefaultInvitationTTL
	}
	if options.InvitationTTL < MinInvitationTTL || options.InvitationTTL > MaxInvitationTTL {
		return nil, fmt.Errorf("%w: 邀请有效期必须在 %s～%s 之间", ErrOptionsInvalid,
			MinInvitationTTL, MaxInvitationTTL)
	}
	if strings.TrimSpace(options.AppName) == "" {
		options.AppName = "EvernightLogin"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{opts: options}, nil
}

// CreateInvitation 创建受控邀请并在成功提交后发送邀请邮件。
//
// 目标邮箱/目标用户二选一；应用非空时角色作用域必须等于该应用，系统范围只能使用
// system 作用域角色。邀请令牌只出现在邮件链接中，不写入日志/数据库明文。
func (s *Service) CreateInvitation(ctx context.Context, caller Caller, request CreateRequest) (CreateResult, error) {
	ctx = normalizeContext(ctx)
	if err := s.authorizeInvite(ctx, caller, request); err != nil {
		return CreateResult{}, err
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return CreateResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	targetKind, targetEmail, targetUserID, err := s.normalizeTarget(ctx, request)
	if err != nil {
		return CreateResult{}, err
	}
	appID := strings.TrimSpace(request.AppID)
	if appID != "" && !app.ValidApplicationID(appID) {
		return CreateResult{}, fmt.Errorf("%w: 应用 ID 格式无效", ErrInvalidRequest)
	}
	roles, err := normalizeRoles(request.Roles, appID)
	if err != nil {
		return CreateResult{}, err
	}
	maxUses := request.MaxUses
	if maxUses == 0 {
		maxUses = DefaultMaxUses
	}
	if maxUses < MinMaxUses || maxUses > MaxMaxUses {
		return CreateResult{}, fmt.Errorf("%w: 使用次数必须在 %d～%d 之间", ErrInvalidRequest, MinMaxUses, MaxMaxUses)
	}
	// 当前邀请令牌是一次性高熵凭证：一封邀请邮件只对应一次接受。多次使用需要为
	// 每个接受者分别签发令牌，留后续步骤；先明确拒绝而不是静默只生效一次。
	if maxUses != 1 {
		return CreateResult{}, fmt.Errorf("%w: 当前版本邀请只能单次使用", ErrInvalidRequest)
	}
	ttl := request.TTL
	if ttl == 0 {
		ttl = s.opts.InvitationTTL
	}
	if ttl < MinInvitationTTL || ttl > MaxInvitationTTL {
		return CreateResult{}, fmt.Errorf("%w: 邀请有效期必须在 %s～%s 之间", ErrInvalidRequest,
			MinInvitationTTL, MaxInvitationTTL)
	}
	invitationID, err := newInvitationID(s.opts.Random)
	if err != nil {
		return CreateResult{}, fmt.Errorf("%w: 无法生成邀请标识", ErrStoreUnavailable)
	}
	now := s.now()
	record := InvitationRecord{
		ID:            invitationID,
		InviterUserID: caller.actor.ID,
		TargetKind:    targetKind,
		TargetEmail:   targetEmail,
		TargetUserID:  targetUserID,
		AppID:         appID,
		Roles:         roles,
		MaxUses:       maxUses,
		ExpiresAt:     now.Add(ttl),
		Now:           now,
		RequestID:     request.RequestID,
	}
	issued, err := s.opts.Credentials.Issue(ctx, credential.IssueRequest{
		Purpose: PurposeInvitationAccept,
		Target:  invitationID,
		Kind:    credential.KindToken,
		TTL:     ttl,
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf("%w: 无法签发邀请令牌", ErrStoreUnavailable)
	}
	acceptanceURL, err := s.buildAcceptanceURL(invitationID, issued.ID, issued.Secret.Reveal())
	if err != nil {
		_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: issued.ID, Purpose: PurposeInvitationAccept, Target: invitationID})
		return CreateResult{}, fmt.Errorf("%w: 无法生成邀请入口地址", ErrOptionsInvalid)
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "invitation.create",
			Target:    audit.Target{Type: "invitation", ID: invitationID},
			RequestID: request.RequestID,
			Changes: []audit.FieldChange{
				{Field: "target_kind", After: string(targetKind)},
				{Field: "target_masked", After: maskTarget(targetKind, targetEmail, targetUserID)},
				{Field: "app_id", After: appID},
				{Field: "max_uses", After: fmt.Sprintf("%d", maxUses)},
			},
		},
		FailureReasonCode: "invitation.create_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		reader, ok := s.opts.Store.(RoleAssignableReader)
		if !ok {
			return fmt.Errorf("%w: 存储不支持角色可分配性检查", ErrOptionsInvalid)
		}
		if err := reader.RoleAssignableTx(txCtx, tx, record.Roles); err != nil {
			return err
		}
		if err := s.checkInvitationCreationTransfer(txCtx, tx, caller, record); err != nil {
			return err
		}
		return s.opts.Store.CreateInvitation(txCtx, tx, record)
	})
	if err != nil {
		_ = s.opts.Credentials.Cancel(context.WithoutCancel(ctx), credential.CancelRequest{
			ID: issued.ID, Purpose: PurposeInvitationAccept, Target: invitationID})
		return CreateResult{}, mapCriticalError(err)
	}
	invitation, found, err := s.opts.Store.GetInvitation(ctx, invitationID)
	if err != nil || !found {
		return CreateResult{}, ErrStoreUnavailable
	}
	result := CreateResult{Invitation: invitation}
	recipient := targetEmail
	if targetKind == TargetUser {
		email, found, err := s.opts.Store.NotificationEmail(ctx, targetUserID)
		if err != nil || !found {
			recipient = ""
		} else {
			recipient = email
		}
	}
	if s.opts.Mailer == nil || recipient == "" {
		result.TokenSent = false
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.recordInvitationNotify(ctx, invitationID, NotifyFailed, result.ErrorCode)
		return result, nil
	}
	sendErr := s.opts.Mailer.SendInvitation(ctx, InvitationEmail{
		InvitationID:  invitationID,
		Recipient:     recipient,
		DisplayName:   "受邀用户",
		AcceptanceURL: acceptanceURL,
		ExpiresAt:     record.ExpiresAt,
		ExpiresIn:     formatDuration(ttl),
		InviterName:   caller.actor.ID,
		AppID:         appID,
		AppName:       s.opts.AppName,
		RequestID:     request.RequestID,
	})
	if sendErr != nil {
		result.TokenSent = false
		result.ErrorCode = string(CodeMailDeliveryFailed)
		s.recordInvitationNotify(ctx, invitationID, NotifyFailed, result.ErrorCode)
		return result, nil
	}
	result.TokenSent = true
	s.recordInvitationNotify(ctx, invitationID, NotifySent, "")
	return result, nil
}

// AcceptInvitation 验证邀请令牌并按当前邀请者权限重新校验后原子接受邀请。
func (s *Service) AcceptInvitation(ctx context.Context, caller Caller, request AcceptRequest) (AcceptResult, error) {
	if !caller.actor.Type.Valid() {
		caller.actor = audit.Actor{Type: audit.ActorAnonymous}
	}
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return AcceptResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.InvitationID) == "" || strings.TrimSpace(request.CredentialID) == "" || request.Token == "" {
		return AcceptResult{}, ErrInvitationNotFound
	}
	now := s.now()
	var newUser *NewUserRecord
	userID := ""
	if request.NewUser != nil {
		userID = ""
		record, err := s.prepareNewUser(*request.NewUser, now)
		if err != nil {
			return AcceptResult{}, err
		}
		newUser = record
	} else {
		if caller.actor.Type != audit.ActorUser {
			return AcceptResult{}, ErrInvitationIdentityMismatch
		}
		userID = caller.actor.ID
	}
	// 令牌消费是身份证明；先做无事务身份预检，避免错误身份的尝试白白消费令牌。
	invitation, found, err := s.opts.Store.GetInvitation(ctx, request.InvitationID)
	if err != nil {
		return AcceptResult{}, ErrStoreUnavailable
	}
	if !found {
		return AcceptResult{}, ErrInvitationNotFound
	}
	if newUser != nil {
		if invitation.TargetKind != TargetEmail {
			return AcceptResult{}, ErrInvitationIdentityMismatch
		}
		// 新账户邮箱固定为邀请目标邮箱（已规范化），并由令牌持有证明控制权。
		newUser.Email = invitation.TargetEmail
		newUser.EmailNormalized = invitation.TargetEmail
	} else {
		switch invitation.TargetKind {
		case TargetUser:
			if invitation.TargetUserID != userID {
				return AcceptResult{}, ErrInvitationIdentityMismatch
			}
		case TargetEmail:
			reader, ok := s.opts.Store.(VerifiedEmailReader)
			if !ok {
				return AcceptResult{}, fmt.Errorf("%w: 存储不支持身份预检", ErrOptionsInvalid)
			}
			verified, err := reader.VerifiedEmail(ctx, userID, invitation.TargetEmail)
			if err != nil {
				return AcceptResult{}, ErrStoreUnavailable
			}
			if !verified {
				return AcceptResult{}, ErrInvitationIdentityMismatch
			}
		default:
			return AcceptResult{}, ErrInvitationIdentityMismatch
		}
	}
	if _, err := s.opts.Credentials.VerifyAndConsume(ctx, credential.VerifyRequest{
		Kind:    credential.KindToken,
		ID:      request.CredentialID,
		Purpose: PurposeInvitationAccept,
		Target:  request.InvitationID,
		Secret:  request.Token,
	}); err != nil {
		if errors.Is(err, credential.ErrStoreUnavailable) {
			return AcceptResult{}, ErrStoreUnavailable
		}
		return AcceptResult{}, ErrInvitationNotFound
	}
	acceptedAt := time.Time{}
	var accepted Invitation
	auditUserID := userID
	if newUser != nil {
		auditUserID = newUser.UserID
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "invitation.accept",
			Target:    audit.Target{Type: "invitation", ID: request.InvitationID},
			RequestID: request.RequestID,
			Changes:   []audit.FieldChange{{Field: "user_id", After: auditUserID}},
		},
		FailureReasonCode: "invitation.accept_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		invitation, found, err := s.opts.Store.LoadInvitationTx(txCtx, tx, request.InvitationID)
		if err != nil {
			return err
		}
		if !found {
			return ErrInvitationNotFound
		}
		if invitation.Status != InvitationPending {
			switch invitation.Status {
			case InvitationCancelled:
				return ErrInvitationCancelled
			case InvitationExpired:
				return ErrInvitationExpired
			}
			return ErrInvitationConflict
		}
		if !now.Before(invitation.ExpiresAt) {
			return ErrInvitationExpired
		}
		if invitation.UsedCount >= invitation.MaxUses {
			return ErrInvitationExhausted
		}
		if invitation.AppID != "" {
			status, found, err := s.opts.Store.AppStatusTx(txCtx, tx, invitation.AppID)
			if err != nil {
				return err
			}
			if !found || !appActive(invitation.AppID, status) {
				return ErrInvitationNotAcceptable
			}
		}
		inviterState, found, err := s.opts.Store.UserStateTx(txCtx, tx, invitation.InviterUserID)
		if err != nil {
			return err
		}
		if !found || inviterState.Status != account.StatusActive {
			return ErrInvitationNotAcceptable
		}
		if newUser != nil {
			if invitation.TargetKind != TargetEmail || invitation.TargetEmail != newUser.EmailNormalized {
				return ErrInvitationIdentityMismatch
			}
		} else {
			state, found, err := s.opts.Store.UserStateTx(txCtx, tx, userID)
			if err != nil {
				return err
			}
			if !found || state.Status != account.StatusActive || state.IsRoot {
				return ErrInvitationIdentityMismatch
			}
			switch invitation.TargetKind {
			case TargetEmail:
				ok, err := s.opts.Store.VerifiedEmailTx(txCtx, tx, userID, invitation.TargetEmail)
				if err != nil {
					return err
				}
				if !ok {
					return ErrInvitationIdentityMismatch
				}
			case TargetUser:
				if invitation.TargetUserID != userID {
					return ErrInvitationIdentityMismatch
				}
			default:
				return ErrInvitationIdentityMismatch
			}
		}
		// 赋权按接受时当前邀请者权限重新校验（delegation.Guard 在同一事务内）。
		// 校验范围 = 目标用户在当前范围既有有效权限 ∪ 邀请角色权限：零角色邀请也会
		// 经过 Guard，避免重新启用停用成员时绕过其保留角色权限的转授检查。
		reader, ok := s.opts.Store.(RoleAssignableReader)
		if !ok {
			return fmt.Errorf("%w: 存储不支持角色可分配性检查", ErrOptionsInvalid)
		}
		if err := reader.RoleAssignableTx(txCtx, tx, invitation.Roles); err != nil {
			return err
		}
		permissions, err := s.opts.Store.RolePermissionsTx(txCtx, tx, invitation.Roles)
		if err != nil {
			return err
		}
		targetUserID := userID
		if newUser != nil {
			targetUserID = newUser.UserID
		}
		scopeID := invitation.AppID
		if scopeID == "" {
			scopeID = "system"
		}
		invitedRefs := flattenRolePermissions(invitation.Roles, permissions)
		existingRefs, err := reader.MemberEffectivePermissionRefsTx(txCtx, tx, scopeID, targetUserID)
		if err != nil {
			return err
		}
		transferRefs := unionPermissionRefs(existingRefs, invitedRefs)
		if err := s.opts.Guard.CheckAssignment(txCtx, tx, audit.Actor{
			Type: audit.ActorUser, ID: invitation.InviterUserID,
		}, scopeID, transferRefs, delegation.Target{Kind: delegation.TargetUser, ID: targetUserID}); err != nil {
			return fmt.Errorf("%w: 邀请者当前无权完成该接受（含目标既有权限）", ErrAccessDenied)
		}
		if err := s.opts.Store.AcceptInvitationTx(txCtx, tx, AcceptParams{
			InvitationID: invitation.ID,
			UserID:       targetUserID,
			NewUser:      newUser,
			Now:          now,
			RequestID:    request.RequestID,
		}); err != nil {
			return err
		}
		accepted = invitation
		acceptedAt = now
		userID = targetUserID
		return nil
	})
	if err != nil {
		return AcceptResult{}, mapCriticalError(err)
	}
	roles := append([]Role(nil), accepted.Roles...)
	s.opts.Logger.Info("邀请已接受", "invitation_id", request.InvitationID,
		"app_id", accepted.AppID, "new_user", newUser != nil)
	return AcceptResult{
		InvitationID: request.InvitationID,
		UserID:       userID,
		NewUser:      newUser != nil,
		AppID:        accepted.AppID,
		Roles:        roles,
		AcceptedAt:   acceptedAt,
	}, nil
}

// CancelInvitation 取消邀请；仅发起者本人或受信系统/本地管理员可取消。
func (s *Service) CancelInvitation(ctx context.Context, caller Caller, request CancelRequest) (CancelResult, error) {
	ctx = normalizeContext(ctx)
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return CancelResult{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.InvitationID) == "" {
		return CancelResult{}, fmt.Errorf("%w: 邀请 ID 不能为空", ErrInvalidRequest)
	}
	if len([]rune(request.Reason)) > 500 {
		return CancelResult{}, fmt.Errorf("%w: 取消理由过长", ErrInvalidRequest)
	}
	invitation, found, err := s.opts.Store.GetInvitation(ctx, request.InvitationID)
	if err != nil {
		return CancelResult{}, ErrStoreUnavailable
	}
	if !found {
		return CancelResult{}, ErrInvitationNotFound
	}
	if !s.canManageInvitation(caller, invitation) {
		return CancelResult{}, ErrAccessDenied
	}
	cancelled := false
	now := s.now()
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     caller.actor,
			Action:    "invitation.cancel",
			Target:    audit.Target{Type: "invitation", ID: request.InvitationID},
			RequestID: request.RequestID,
			Changes:   []audit.FieldChange{{Field: "reason", After: maskText(request.Reason)}},
		},
		FailureReasonCode: "invitation.cancel_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapCriticalError(err)))
		},
	}
	err = s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		ok, err := s.opts.Store.CancelInvitation(txCtx, tx, CancelParams{
			InvitationID: request.InvitationID,
			Reason:       request.Reason,
			Actor:        caller.actor,
			Now:          now,
			RequestID:    request.RequestID,
		})
		if err != nil {
			return err
		}
		cancelled = ok
		return nil
	})
	if err != nil {
		return CancelResult{}, mapCriticalError(err)
	}
	updated, found, err := s.opts.Store.GetInvitation(ctx, request.InvitationID)
	if err != nil || !found {
		return CancelResult{}, ErrStoreUnavailable
	}
	return CancelResult{Invitation: updated, Cancelled: cancelled}, nil
}

// GetInvitation 读取邀请；用户身份只能读自己发起的邀请。
func (s *Service) GetInvitation(ctx context.Context, caller Caller, invitationID string) (Invitation, error) {
	ctx = normalizeContext(ctx)
	invitation, found, err := s.opts.Store.GetInvitation(ctx, invitationID)
	if err != nil {
		return Invitation{}, ErrStoreUnavailable
	}
	if !found {
		return Invitation{}, ErrInvitationNotFound
	}
	if !s.canManageInvitation(caller, invitation) {
		return Invitation{}, ErrAccessDenied
	}
	return invitation, nil
}

// ListInvitations 列出邀请；用户身份只能列自己发起的邀请。
func (s *Service) ListInvitations(ctx context.Context, caller Caller, request ListRequest) (ListResult, error) {
	ctx = normalizeContext(ctx)
	if err := caller.actor.Validate(); err != nil {
		return ListResult{}, ErrAccessDenied
	}
	inviter := ""
	if caller.actor.Type == audit.ActorUser {
		inviter = caller.actor.ID
	} else if caller.actor.Type != audit.ActorSystem && caller.actor.Type != audit.ActorLocalAdmin {
		return ListResult{}, ErrAccessDenied
	}
	if request.Limit == 0 {
		request.Limit = DefaultListLimit
	}
	if request.Limit < 1 || request.Limit > MaxListLimit || request.Offset < 0 {
		return ListResult{}, fmt.Errorf("%w: 分页参数无效", ErrInvalidRequest)
	}
	if request.Status != "" && !request.Status.Valid() {
		return ListResult{}, fmt.Errorf("%w: 邀请状态无效", ErrInvalidRequest)
	}
	result, err := s.opts.Store.ListInvitations(ctx, inviter, request)
	if err != nil {
		return ListResult{}, ErrStoreUnavailable
	}
	return result, nil
}

// authorizeInvite 校验创建邀请权限：注入授权器优先；未注入时仅受信系统/本地管理员。
func (s *Service) authorizeInvite(ctx context.Context, caller Caller, request CreateRequest) error {
	if err := caller.actor.Validate(); err != nil {
		return ErrAccessDenied
	}
	if s.opts.InviteAuthorizer != nil {
		return s.opts.InviteAuthorizer.AuthorizeInvite(ctx, caller, request)
	}
	if caller.actor.Type == audit.ActorSystem || caller.actor.Type == audit.ActorLocalAdmin {
		return nil
	}
	return ErrAccessDenied
}

// canManageInvitation 报告调用者能否读取/取消该邀请：发起者本人或受信管理通道。
func (s *Service) canManageInvitation(caller Caller, invitation Invitation) bool {
	switch caller.actor.Type {
	case audit.ActorUser:
		return caller.actor.ID == invitation.InviterUserID
	case audit.ActorSystem, audit.ActorLocalAdmin:
		return true
	default:
		return false
	}
}

// normalizeTarget 校验目标邮箱/目标用户二选一。
func (s *Service) normalizeTarget(ctx context.Context, request CreateRequest) (TargetKind, string, string, error) {
	email := strings.TrimSpace(request.TargetEmail)
	userID := strings.TrimSpace(request.TargetUserID)
	if (email == "") == (userID == "") {
		return "", "", "", fmt.Errorf("%w: 目标邮箱与目标用户必须二选一", ErrInvalidRequest)
	}
	if email != "" {
		_, normalized, err := authn.NormalizeEmail(email)
		if err != nil {
			return "", "", "", fmt.Errorf("%w: 目标邮箱格式无效", ErrInvalidRequest)
		}
		return TargetEmail, normalized, "", nil
	}
	if !account.ValidUserID(userID) {
		return "", "", "", fmt.Errorf("%w: 目标用户 ID 格式无效", ErrInvalidRequest)
	}
	state, found, err := s.userState(ctx, userID)
	if err != nil {
		return "", "", "", err
	}
	if !found || state.Status != account.StatusActive || state.IsRoot {
		return "", "", "", fmt.Errorf("%w: 目标用户不可邀请", ErrInvalidRequest)
	}
	if _, hasEmail, err := s.opts.Store.NotificationEmail(ctx, userID); err != nil || !hasEmail {
		return "", "", "", fmt.Errorf("%w: 目标用户没有可用于接收邀请的邮箱", ErrInvalidRequest)
	}
	return TargetUser, "", userID, nil
}

// userState 在无事务路径读取账户状态（仅用于创建前快速校验）。
func (s *Service) userState(ctx context.Context, userID string) (UserState, bool, error) {
	return s.opts.Store.UserState(ctx, userID)
}

// prepareNewUser 校验由邀请创建新账户的字段并生成哈希；不写库。
func (s *Service) prepareNewUser(request NewUserRequest, now time.Time) (*NewUserRecord, error) {
	username, normalized, err := account.NormalizeUsername(request.Username)
	if err != nil {
		return nil, err
	}
	nickname, err := account.NormalizeNickname(request.Nickname)
	if err != nil {
		return nil, err
	}
	language, err := account.NormalizeLanguage(request.Language)
	if err != nil {
		return nil, err
	}
	timezone, err := account.NormalizeTimezone(request.Timezone)
	if err != nil {
		return nil, err
	}
	if err := s.opts.PasswordPolicy.Check(request.Password, []string{username, nickname}); err != nil {
		if errors.Is(err, authn.ErrInvalidRequest) {
			return nil, fmt.Errorf("%w: 密码格式无效", ErrInvalidRequest)
		}
		return nil, fmt.Errorf("%w: 密码不符合强度要求", ErrWeakPassword)
	}
	hash, err := authn.HashPassword(request.Password, s.opts.HashParams, s.opts.Random)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法生成密码哈希", ErrStoreUnavailable)
	}
	userID, err := account.NewUserID(s.opts.Random)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法生成用户标识", ErrStoreUnavailable)
	}
	return &NewUserRecord{
		UserID:             userID,
		Username:           username,
		UsernameNormalized: normalized,
		Nickname:           nickname,
		Language:           language,
		Timezone:           timezone,
		PasswordHash:       hash,
	}, nil
}

// normalizeRoles 校验并去重角色列表，并校验作用域与应用一致。
func normalizeRoles(roles []Role, appID string) ([]Role, error) {
	if len(roles) > MaxInvitationRoles {
		return nil, fmt.Errorf("%w: 角色数量超过 %d 个", ErrInvalidRequest, MaxInvitationRoles)
	}
	seen := make(map[string]struct{}, len(roles))
	normalized := make([]Role, 0, len(roles))
	for _, role := range roles {
		if !validRole(role) {
			return nil, fmt.Errorf("%w: 角色 ID 或作用域无效", ErrInvalidRequest)
		}
		role.RoleID = strings.TrimSpace(role.RoleID)
		role.ScopeID = strings.TrimSpace(role.ScopeID)
		if appID == "" {
			if role.ScopeID != "system" {
				return nil, fmt.Errorf("%w: 系统范围邀请只能使用 system 作用域角色", ErrInvalidRequest)
			}
		} else if role.ScopeID != appID {
			return nil, fmt.Errorf("%w: 应用邀请的角色作用域必须等于应用 ID", ErrInvalidRequest)
		}
		key := role.ScopeID + "/" + role.RoleID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, role)
	}
	return normalized, nil
}

// buildAcceptanceURL 把邀请令牌拼接到配置的接受入口地址；令牌不写日志。
func (s *Service) buildAcceptanceURL(invitationID, credentialID, token string) (string, error) {
	base, err := url.Parse(s.opts.AcceptanceURLBase)
	if err != nil {
		return "", err
	}
	query := base.Query()
	query.Set("iid", invitationID)
	query.Set("cid", credentialID)
	query.Set("token", token)
	base.RawQuery = query.Encode()
	base.Fragment = ""
	return base.String(), nil
}

// recordInvitationNotify 记录邀请通知结果；失败只写运行日志，不影响邀请主事务。
func (s *Service) recordInvitationNotify(ctx context.Context, id string, state NotifyState, code string) {
	if err := s.opts.Store.MarkInvitationNotify(context.WithoutCancel(ctx), id, state, code, s.now()); err != nil {
		s.opts.Logger.Warn("记录邀请通知状态失败", "invitation_id", id)
	}
}

// now 返回 UTC 截断到毫秒的当前时间。
func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

// normalizeContext 把 nil ctx 当成 Background。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// newInvitationID 生成 inv_ + 128 位十六进制随机标识。
func newInvitationID(random io.Reader) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	const hexDigits = "0123456789abcdef"
	var builder strings.Builder
	builder.WriteString("inv_")
	for _, value := range buffer {
		builder.WriteByte(hexDigits[value>>4])
		builder.WriteByte(hexDigits[value&0x0f])
	}
	return builder.String(), nil
}

// formatDuration 把时长格式化为邮件展示用文本。
func formatDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%d 小时", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d/time.Minute))
	}
	return d.String()
}

// maskTarget 生成审计可用的目标脱敏值。
func maskTarget(kind TargetKind, email, userID string) string {
	if kind == TargetUser {
		if len(userID) <= 8 {
			return "usr_***"
		}
		return userID[:8] + "***"
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "[REDACTED]"
	}
	return email[:1] + "***" + email[at:]
}

// maskText 限制审计差异中的自由文本长度。
func maskText(value string) string {
	if len([]rune(value)) > 100 {
		return "[TRUNCATED]"
	}
	return value
}

// mapCriticalError 把审计/存储错误映射为稳定领域错误（审计失败优先）。
func mapCriticalError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, ErrInvitationNotFound), errors.Is(err, ErrInvitationExpired),
		errors.Is(err, ErrInvitationCancelled), errors.Is(err, ErrInvitationExhausted),
		errors.Is(err, ErrInvitationNotAcceptable), errors.Is(err, ErrInvitationIdentityMismatch),
		errors.Is(err, ErrInvitationConflict), errors.Is(err, ErrReviewNotFound),
		errors.Is(err, ErrReviewStateConflict), errors.Is(err, ErrSelfApproval),
		errors.Is(err, ErrAccessDenied), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrMailUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrStoreUnavailable):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

// acceptanceURLProblem 校验邮件入口基础地址。
func acceptanceURLProblem(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "入口地址不能为空"
	}
	if len(value) > 2048 {
		return "入口地址超过 2048 字节"
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return "入口地址包含空白或控制字符"
		}
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "入口地址不是合法 URL"
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "入口地址只允许 http/https"
	}
	if parsed.Host == "" {
		return "入口地址缺少主机名"
	}
	if parsed.User != nil {
		return "入口地址不得包含用户名/口令"
	}
	if parsed.Fragment != "" {
		return "入口地址不得包含片段"
	}
	return ""
}

// isNil 检测 nil 接口与 typed nil 指针。
func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// checkInvitationCreationTransfer 在创建邀请事务内按当前发起者检查可委派范围：
// 已有目标用户时按目标既有权限 ∪ 角色权限做 CheckAssignment；邮箱邀请目标未知时
// 用 CheckPermissionAccess 校验发起者对每个权限的资格与当前持有，避免外发超范围邀请。
func (s *Service) checkInvitationCreationTransfer(ctx context.Context, tx audit.Tx, caller Caller, record InvitationRecord) error {
	scopeID := record.AppID
	if scopeID == "" {
		scopeID = "system"
	}
	permissions, err := s.opts.Store.RolePermissionsTx(ctx, tx, record.Roles)
	if err != nil {
		return err
	}
	roleRefs := flattenRolePermissions(record.Roles, permissions)
	if record.TargetKind == TargetUser {
		reader, ok := s.opts.Store.(RoleAssignableReader)
		if !ok {
			return fmt.Errorf("%w: 存储不支持成员权限读取", ErrOptionsInvalid)
		}
		existingRefs, err := reader.MemberEffectivePermissionRefsTx(ctx, tx, scopeID, record.TargetUserID)
		if err != nil {
			return err
		}
		refs := unionPermissionRefs(existingRefs, roleRefs)
		if err := s.opts.Guard.CheckAssignment(ctx, tx, caller.actor, scopeID, refs,
			delegation.Target{Kind: delegation.TargetUser, ID: record.TargetUserID}); err != nil {
			return fmt.Errorf("%w: 发起者当前无权邀请该目标或分配这些角色", ErrAccessDenied)
		}
		return nil
	}
	if len(record.Roles) == 0 {
		return nil
	}
	// 即使角色当前没有任何权限也调用 Guard（保持“每个角色/应用都检查”的口径，
	// 防止未来角色组合权限变化时出现未检查的创建路径）。
	if err := s.opts.Guard.CheckPermissionAccess(ctx, tx, caller.actor, scopeID, roleRefs, nil); err != nil {
		return fmt.Errorf("%w: 发起者当前无权分配这些角色", ErrAccessDenied)
	}
	return nil
}

// flattenRolePermissions 把按角色分组的权限引用展开并去重。
func flattenRolePermissions(roles []Role, permissions map[string][]delegation.PermissionRef) []delegation.PermissionRef {
	refs := make([]delegation.PermissionRef, 0, len(permissions))
	for _, role := range roles {
		for _, ref := range permissions[role.RoleID] {
			refs = append(refs, ref)
		}
	}
	return dedupePermissionRefs(refs)
}

// unionPermissionRefs 合并两组权限引用并按权限 ID + 数据范围去重。
func unionPermissionRefs(groups ...[]delegation.PermissionRef) []delegation.PermissionRef {
	var refs []delegation.PermissionRef
	for _, group := range groups {
		refs = append(refs, group...)
	}
	return dedupePermissionRefs(refs)
}

// dedupePermissionRefs 去重权限引用，保留首次出现的顺序。
func dedupePermissionRefs(refs []delegation.PermissionRef) []delegation.PermissionRef {
	seen := make(map[string]struct{}, len(refs))
	result := make([]delegation.PermissionRef, 0, len(refs))
	for _, ref := range refs {
		key := ref.PermissionID + "\x00" + ref.DataScopeJSON
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ref)
	}
	return result
}
