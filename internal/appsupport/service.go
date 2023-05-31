// Package appsupport 实现应用受限客服 API 的领域服务与 HTTP 传输（步骤 154）。
//
// 边界：
//   - 认证主体只能来自 OAuth 用户委托 Access Token：ClientID=应用、Subject=staff、
//     aud=应用客服资源；app_id 只来自已验证 token 的 ClientID，绝不接受路径/请求头/
//     query 自称。Token 校验、在线撤销、应用成员与当前应用权限由宿主的真实
//     TokenValidator 实现联合判定。
//   - 应用只能创建本应用的人工升级申请；不能直接改密码、解除 MFA、读取恢复链接/
//     验证码、批准或执行全局恢复。全局恢复审批/执行必须走系统 recovery.approve，
//     本 API 的 approve 路由一律拒绝。
//   - 工单 application_id 为空表示既有系统/全局工单；应用 API 只能访问本应用。
package appsupport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// 稳定错误。
var (
	ErrInvalidRequest      = errors.New("应用客服请求无效")
	ErrAccessDenied        = errors.New("应用客服请求未获准")
	ErrIdentityUnavailable = errors.New("客服身份/令牌暂时不可用")
	ErrGlobalApprovalOnly  = errors.New("全局恢复审批/执行必须由系统 recovery.approve 完成")
	ErrStoreUnavailable    = errors.New("应用客服存储暂时不可用")
)

// PermissionCasesCreate/Read 是应用作用域客服权限键（由 authz 与应用角色显式授予）。
const (
	PermissionCasesCreate = "support.cases.create"
	PermissionCasesRead   = "support.cases.read"
)

// DefaultAudience 是应用客服资源的默认 OAuth audience；应用 OAuth 客户端必须
// 登记该 audience 才能获得可用于本 API 的委托 Access Token。
const DefaultAudience = "urn:evernight:app-support"

const (
	maxReasonBytes = 2000
	maxCaseIDBytes = 96
)

// Identity 是已验证 OAuth 用户委托令牌的不可自述身份。
type Identity struct {
	ApplicationID string
	StaffUserID   string
}

// TokenValidator 由宿主真实实现：验证 Access Token（签名/issuer/aud/类型/有效期/
// 在线撤销）、客户端应用、用户成员关系与应用作用域权限。失败必须返回错误；
// 未实现或依赖故障一律失败关闭。
type TokenValidator interface {
	ValidateToken(ctx context.Context, rawToken string) (Identity, error)
}

// MembershipChecker 判定目标用户当前是否为该应用的有效成员。
type MembershipChecker interface {
	IsActiveMember(ctx context.Context, applicationID, userID string) (bool, error)
}

// PermissionChecker 判定客服用户在应用作用域是否持有指定权限。
type PermissionChecker interface {
	CheckApplicationPermission(ctx context.Context, applicationID, userID,
		permission string) error
}

// TargetProtector 识别禁止应用客服处理的高权限/root 目标；未注入时拒绝构造。
type TargetProtector interface {
	Protected(ctx context.Context, targetUserID string) (bool, error)
}

// Options 是应用客服服务依赖；所有安全依赖缺失均拒绝构造。
type Options struct {
	Store           support.Store
	Audit           support.AuditRecorder
	Tokens          TokenValidator
	Membership      MembershipChecker
	Permissions     PermissionChecker
	TargetProtector TargetProtector
	Now             func() time.Time
	Random          io.Reader
	Logger          *slog.Logger
}

// Service 是应用受限客服服务；无后台任务、不签发会话。
type Service struct {
	opts Options
}

// New 校验依赖并构造服务。
func New(options Options) (*Service, error) {
	if isNil(options.Store) || isNil(options.Audit) || isNil(options.Tokens) ||
		isNil(options.Membership) || isNil(options.Permissions) ||
		isNil(options.TargetProtector) {
		return nil, fmt.Errorf("%w: 应用客服缺少存储/审计/令牌/成员/权限/目标保护依赖",
			ErrInvalidRequest)
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

// CreateCaseRequest 是应用升级申请的白名单请求；不包含密码/MFA/恢复链接/新密码等字段。
type CreateCaseRequest struct {
	TargetUserID string
	Reason       string
	RequestID    string
}

// CaseView 是返回给应用客服的脱敏工单视图。
type CaseView struct {
	ID                   string             `json:"id"`
	ApplicationID        string             `json:"application_id"`
	TargetUserID         string             `json:"target_user_id"`
	TargetMaskedUsername string             `json:"target_masked_username"`
	TargetMaskedEmail    string             `json:"target_masked_email"`
	Reason               string             `json:"reason"`
	Status               support.CaseStatus `json:"status"`
	AssigneeUserID       string             `json:"assignee_user_id"`
	CreatedByUserID      string             `json:"created_by_user_id"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
	RowVersion           int64              `json:"row_version"`
}

// CreateCase 创建本应用人工升级申请（status=manual_review）；不执行任何全局恢复。
func (s *Service) CreateCase(ctx context.Context, rawToken string,
	request CreateCaseRequest) (CaseView, error) {
	identity, err := s.opts.Tokens.ValidateToken(ctx, rawToken)
	if err != nil {
		return CaseView{}, ErrIdentityUnavailable
	}
	if err := account.ValidateRequestID(request.RequestID); err != nil {
		return CaseView{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	if !account.ValidUserID(request.TargetUserID) {
		return CaseView{}, fmt.Errorf("%w: 目标用户标识无效", ErrInvalidRequest)
	}
	if request.TargetUserID == identity.StaffUserID {
		return CaseView{}, ErrAccessDenied
	}
	reason := strings.TrimSpace(request.Reason)
	if len(reason) == 0 || len([]byte(reason)) > maxReasonBytes {
		return CaseView{}, fmt.Errorf("%w: 原因长度无效", ErrInvalidRequest)
	}
	if err := s.opts.Permissions.CheckApplicationPermission(ctx, identity.ApplicationID,
		identity.StaffUserID, PermissionCasesCreate); err != nil {
		return CaseView{}, ErrAccessDenied
	}
	staffMember, err := s.opts.Membership.IsActiveMember(ctx, identity.ApplicationID,
		identity.StaffUserID)
	if err != nil {
		return CaseView{}, ErrIdentityUnavailable
	}
	if !staffMember {
		return CaseView{}, ErrAccessDenied
	}
	targetMember, err := s.opts.Membership.IsActiveMember(ctx, identity.ApplicationID,
		request.TargetUserID)
	if err != nil {
		return CaseView{}, ErrIdentityUnavailable
	}
	if !targetMember {
		return CaseView{}, ErrAccessDenied
	}
	protected, err := s.opts.TargetProtector.Protected(ctx, request.TargetUserID)
	if err != nil || protected {
		return CaseView{}, ErrAccessDenied
	}
	target, found, err := s.opts.Store.LookupTarget(ctx, request.TargetUserID)
	if err != nil || !found || target.IsRoot || target.Status != "active" {
		return CaseView{}, ErrAccessDenied
	}
	caseID, err := newID(s.opts.Random, "sup_", 16)
	if err != nil {
		return CaseView{}, ErrStoreUnavailable
	}
	eventID, err := newID(s.opts.Random, "spe_", 16)
	if err != nil {
		return CaseView{}, ErrStoreUnavailable
	}
	now := s.opts.Now().UTC().Truncate(time.Millisecond)
	record := support.CaseRecord{
		ID: caseID, ApplicationID: identity.ApplicationID,
		TargetUserID: target.UserID, TargetUsername: target.Username,
		CreatedByUserID: identity.StaffUserID, AssigneeUserID: identity.StaffUserID,
		TargetMaskedEmail: maskEmail(target.VerifiedEmail), Reason: reason,
		Status: support.StatusManualReview, RowVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	event := support.EventRecord{ID: eventID, CaseID: caseID,
		Action: "support.app.escalated", Actor: audit.Actor{Type: audit.ActorUser,
			ID: identity.StaffUserID}, ToStatus: support.StatusManualReview,
		Detail: "应用客服创建人工升级申请（未执行全局恢复）", CreatedAt: now}
	critical := audit.CriticalRequest{Event: audit.Event{
		Actor: event.Actor, AppID: identity.ApplicationID, Action: "support.app.case.created",
		Target: audit.Target{Type: "support_case", ID: caseID}, RequestID: request.RequestID,
		Changes: []audit.FieldChange{
			{Field: "application_id", After: identity.ApplicationID},
			{Field: "target_user_id", After: target.UserID},
			{Field: "status", After: string(support.StatusManualReview)},
		},
	}, FailureReasonCode: "support.app.case_create_failed",
		FailureErrorCodeFor: func(err error) string { return "INTERNAL_ERROR" }}
	if err := s.opts.Audit.ExecuteCritical(ctx, critical, func(txCtx context.Context,
		tx audit.Tx) error {
		return s.opts.Store.CreateCaseTx(txCtx, tx, record, event)
	}); err != nil {
		return CaseView{}, ErrStoreUnavailable
	}
	return viewOf(record), nil
}

// GetCase 读取本应用工单；跨应用统一拒绝，不泄露存在性。
func (s *Service) GetCase(ctx context.Context, rawToken, caseID string) (CaseView, error) {
	identity, err := s.opts.Tokens.ValidateToken(ctx, rawToken)
	if err != nil {
		return CaseView{}, ErrIdentityUnavailable
	}
	if err := s.checkRead(ctx, identity); err != nil {
		return CaseView{}, err
	}
	if strings.TrimSpace(caseID) == "" || len(caseID) > maxCaseIDBytes {
		return CaseView{}, ErrInvalidRequest
	}
	record, found, err := s.opts.Store.GetCase(ctx, caseID)
	if err != nil {
		return CaseView{}, ErrStoreUnavailable
	}
	if !found || record.ApplicationID != identity.ApplicationID {
		return CaseView{}, ErrAccessDenied
	}
	return viewOf(record), nil
}

// ListCases 分页列出本应用工单；不允许跨应用/系统工单查询。
func (s *Service) ListCases(ctx context.Context, rawToken string,
	offset, limit int) ([]CaseView, bool, error) {
	identity, err := s.opts.Tokens.ValidateToken(ctx, rawToken)
	if err != nil {
		return nil, false, ErrIdentityUnavailable
	}
	if err := s.checkRead(ctx, identity); err != nil {
		return nil, false, err
	}
	if offset < 0 || offset > 1_000_000 || limit < 1 || limit > 100 {
		return nil, false, fmt.Errorf("%w: 分页参数无效", ErrInvalidRequest)
	}
	records, hasMore, err := s.opts.Store.ListCases(ctx, support.CaseQuery{
		ApplicationID: identity.ApplicationID, Limit: limit, Offset: offset})
	if err != nil {
		return nil, false, ErrStoreUnavailable
	}
	views := make([]CaseView, 0, len(records))
	for _, record := range records {
		if record.ApplicationID != identity.ApplicationID {
			continue
		}
		views = append(views, viewOf(record))
	}
	return views, hasMore, nil
}

// Approve 明确拒绝：应用管理员不能审批/执行全局恢复，必须由系统 recovery.approve。
func (s *Service) Approve(context.Context, string, string, string) error {
	return ErrGlobalApprovalOnly
}

func (s *Service) checkRead(ctx context.Context, identity Identity) error {
	if err := s.opts.Permissions.CheckApplicationPermission(ctx, identity.ApplicationID,
		identity.StaffUserID, PermissionCasesRead); err != nil {
		return ErrAccessDenied
	}
	active, err := s.opts.Membership.IsActiveMember(ctx, identity.ApplicationID,
		identity.StaffUserID)
	if err != nil {
		return ErrIdentityUnavailable
	}
	if !active {
		return ErrAccessDenied
	}
	return nil
}

func viewOf(record support.CaseRecord) CaseView {
	return CaseView{ID: record.ID, ApplicationID: record.ApplicationID,
		TargetUserID:         record.TargetUserID,
		TargetMaskedUsername: maskUsername(record.TargetUsername),
		TargetMaskedEmail:    record.TargetMaskedEmail, Reason: record.Reason,
		Status: record.Status, AssigneeUserID: record.AssigneeUserID,
		CreatedByUserID: record.CreatedByUserID, CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt, RowVersion: record.RowVersion}
}

func newID(random io.Reader, prefix string, bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func maskUsername(username string) string {
	trimmed := strings.TrimSpace(username)
	if trimmed == "" {
		return "[REDACTED]"
	}
	runes := []rune(trimmed)
	if len(runes) > 2 {
		return string(runes[:2]) + "***"
	}
	return string(runes[:1]) + "***"
}

func maskEmail(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 || at == len(address)-1 {
		return "[REDACTED]"
	}
	return string(address[0]) + "***@" + address[at+1:]
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	type nilable interface{ IsNil() bool }
	_ = nilable(nil)
	return false
}
