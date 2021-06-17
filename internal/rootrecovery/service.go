package rootrecovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/authn"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

// Options 是 root 应急恢复服务依赖。数据库由服务在恢复期间独占打开；审计使用同一
// 数据库的 audit_events 表，成功变更与审计一致提交。
type Options struct {
	// DatabasePath 是目标 SQLite 数据库文件路径；必须已存在且为本项目实例。
	DatabasePath string
	// Operator 是本地应急操作者审计身份（OS 用户/机器名），不含秘密。
	Operator Operator
	// Prompter 负责范围确认与隐藏密码输入；必填（生产为终端实现）。
	Prompter Prompter
	// Now 是可注入时钟；nil 使用 time.Now。
	Now func() time.Time
	// Random 是密码盐/请求编号随机源；nil 使用 crypto/rand.Reader。
	Random io.Reader
	// Logger 是结构化运行日志；不得记录密码或秘密。
	Logger *slog.Logger
	// PasswordPolicy は新密码策略；零值使用 authn.DefaultPasswordPolicy。
	PasswordPolicy authn.PasswordPolicy
	// TestOnlyFaultInjector 仅限测试注入事务中途失败以验证整体回滚；生产必须为 nil。
	// 它在指定阶段返回错误时代码返回错误并让审计事务整体回滚。
	TestOnlyFaultInjector func(stage string) error
}

// Service 是 root 本地应急恢复服务。构造后不可变，不启动协程、不暴露 HTTP 接口。
type Service struct {
	opts Options
}

// New 校验选项并构造服务；不会打开数据库或执行恢复。
func New(options Options) (*Service, error) {
	if strings.TrimSpace(options.DatabasePath) == "" {
		return nil, fmt.Errorf("%w: 数据库路径为空", ErrOptionsInvalid)
	}
	absolute, err := filepath.Abs(options.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法解析数据库路径", ErrOptionsInvalid)
	}
	options.DatabasePath = absolute
	if err := options.Operator.Validate(); err != nil {
		return nil, err
	}
	if isNilInterface(options.Prompter) {
		return nil, fmt.Errorf("%w: 交互确认器为空", ErrOptionsInvalid)
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
	if options.PasswordPolicy.MinRunes == 0 && options.PasswordPolicy.MaxRunes == 0 &&
		options.PasswordPolicy.HistoryLimit == 0 && len(options.PasswordPolicy.WeakExtraWords) == 0 {
		options.PasswordPolicy = authn.DefaultPasswordPolicy()
	}
	if err := options.PasswordPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: 密码策略无效", ErrOptionsInvalid)
	}
	return &Service{opts: options}, nil
}

// Recover 执行一次本地 root 应急恢复。调用顺序：验证请求 → 取得排他锁 → 校验数据库/
// 实例 → 显式确认（含 Passkey 二次确认）→ 隐藏输入新密码（如选择）→ 单一审计事务内
// 完成全部安全变更与恢复记录 → 释放锁。取消确认、错误数据库与锁冲突都不会修改数据库。
func (s *Service) Recover(ctx context.Context, request Request) (Result, error) {
	ctx = normalizeContext(ctx)
	if err := s.validateRequest(request); err != nil {
		return Result{}, err
	}
	reason, err := validReason(request.Reason)
	if err != nil {
		return Result{}, err
	}
	now := s.now()
	lock, err := acquireLock(s.opts.DatabasePath, s.opts.Operator, now)
	if err != nil {
		return Result{}, err
	}
	defer lock.Release()

	store, err := openRecoveryStore(ctx, s.opts.DatabasePath)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = store.Close() }()

	info, err := validateDatabase(ctx, store)
	if err != nil {
		return Result{}, err
	}
	auditStore, err := auditsqlite.New(store)
	if err != nil {
		return Result{}, ErrStoreUnavailable
	}
	recorder, err := audit.New(auditStore, audit.Options{
		Now: func() time.Time { return s.now() }, Logger: s.opts.Logger,
	})
	if err != nil {
		return Result{}, ErrOptionsInvalid
	}

	// 范围摘要确认：取消不产生任何数据库修改（包括不写失败审计，保持“零修改”）。
	allowed, err := s.opts.Prompter.ConfirmRecovery(ScopeSummary{
		DatabasePath: s.opts.DatabasePath, Operator: s.opts.Operator,
		RootUsername: info.RootUsername, ResetPassword: request.ResetPassword,
		ResetMFA: request.ResetMFA, RevokeLoginPasskeys: request.RevokeLoginPasskeys,
		CurrentState: info.InitializationState,
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: 交互确认失败", ErrInvalidRequest)
	}
	if !allowed {
		return Result{}, ErrConfirmationDeclined
	}
	if request.RevokeLoginPasskeys {
		confirmed, confirmErr := s.opts.Prompter.ConfirmPasskeyRevocation()
		if confirmErr != nil {
			return Result{}, fmt.Errorf("%w: Passkey 撤销确认失败", ErrInvalidRequest)
		}
		if !confirmed {
			return Result{}, ErrConfirmationDeclined
		}
	}
	passwordHash := ""
	if request.ResetPassword {
		first, readErr := s.opts.Prompter.ReadNewPassword()
		if readErr != nil {
			zeroBytes(first)
			return Result{}, fmt.Errorf("%w: 读取新密码失败", ErrInvalidRequest)
		}
		second, readErr := s.opts.Prompter.ReadNewPassword()
		if readErr != nil {
			zeroBytes(first)
			zeroBytes(second)
			return Result{}, fmt.Errorf("%w: 读取新密码失败", ErrInvalidRequest)
		}
		// 使用后立即尽力清零；string 转换用于策略校验/哈希，Go 无法保证这些副本
		// 的驻留期（README 已声明边界）。
		matches := len(first) == len(second) && subtle.ConstantTimeCompare(first, second) == 1
		zeroBytes(second)
		if !matches {
			zeroBytes(first)
			return Result{}, fmt.Errorf("%w: 两次输入的新密码不一致", ErrPasswordPolicy)
		}
		policyErr := checkPasswordPolicy(s.opts.PasswordPolicy, string(first), info.RootUsername)
		if policyErr != nil {
			zeroBytes(first)
			return Result{}, policyErr
		}
		hash, hashErr := authn.HashPassword(string(first), authn.DefaultParams(), s.opts.Random)
		zeroBytes(first)
		if hashErr != nil {
			return Result{}, fmt.Errorf("%w: 生成新密码哈希失败", ErrOptionsInvalid)
		}
		passwordHash = hash
	}

	eventID, err := s.newID("rre_")
	if err != nil {
		return Result{}, err
	}
	requestID := request.RequestID
	if requestID == "" {
		if requestID, err = s.newRequestID(); err != nil {
			return Result{}, err
		}
	}
	actions := recoveryActions{Password: request.ResetPassword, MFA: request.ResetMFA,
		Passkeys: request.RevokeLoginPasskeys}
	actionsJSON, err := json.Marshal(actions)
	if err != nil {
		return Result{}, fmt.Errorf("%w: 无法编码恢复范围", ErrOptionsInvalid)
	}

	// 审计差异字段有长度上限：完整原因保存在 root_recovery_events（≤500 字符），
	// 审计只保留安全截断摘要，避免长原因导致事件无效而 fail-closed。
	changes := []audit.FieldChange{
		{Field: "reason", After: truncateRunes(reason, 80)},
		{Field: "operator_machine", After: truncateRunes(s.opts.Operator.Machine, 64)},
		{Field: "password_reset", After: fmt.Sprint(request.ResetPassword)},
		{Field: "mfa_reset", After: fmt.Sprint(request.ResetMFA)},
		{Field: "passkeys_revoked", After: fmt.Sprint(request.RevokeLoginPasskeys)},
		{Field: "recovery_event", After: eventID},
	}
	critical := audit.CriticalRequest{
		Event: audit.Event{
			Actor:     audit.Actor{Type: audit.ActorLocalAdmin, ID: s.opts.Operator.ID},
			Action:    "root.emergency_recovery",
			Target:    audit.Target{Type: "user", ID: info.RootUserID},
			RequestID: requestID,
			Changes:   changes,
		},
		FailureReasonCode: "root_emergency_recovery_failed",
		FailureErrorCodeFor: func(err error) string {
			return string(CodeOf(mapRecoveryError(err)))
		},
	}
	result := Result{EventID: eventID, RootUserID: info.RootUserID, CompletedAt: now}
	err = recorder.ExecuteCritical(ctx, critical, func(txCtx context.Context, tx audit.Tx) error {
		if request.ResetPassword {
			if err := s.applyPassword(txCtx, tx, info.RootUserID, passwordHash, now); err != nil {
				return err
			}
			if err := s.fault(faultAfterPassword); err != nil {
				return err
			}
		}
		factorsDisabled, groupsRevoked, err := s.applyMFAAndRecoveryReset(txCtx, tx,
			info.RootUserID, request.ResetMFA, now)
		if err != nil {
			return err
		}
		result.FactorsDisabled = factorsDisabled
		result.RecoveryCodeGroupsRevoked = groupsRevoked
		if err := s.fault(faultAfterFactors); err != nil {
			return err
		}
		sessionsRevoked, err := s.revokeSessions(txCtx, tx, info.RootUserID, now)
		if err != nil {
			return err
		}
		result.SessionsRevoked = sessionsRevoked
		passkeysRevoked := int64(0)
		if request.RevokeLoginPasskeys {
			if passkeysRevoked, err = s.revokePasskeys(txCtx, tx, info.RootUserID, now); err != nil {
				return err
			}
		}
		result.PasskeysRevoked = passkeysRevoked
		if err := s.fault(faultAfterSessions); err != nil {
			return err
		}
		securityVersion, err := s.bumpSecurityVersion(txCtx, tx, info.RootUserID, now)
		if err != nil {
			return err
		}
		result.SecurityVersionAfter = securityVersion
		if err := s.forceReconfigureState(txCtx, tx, info.RootUserID, now); err != nil {
			return err
		}
		if err := s.revokeOneTimeCredentials(txCtx, tx, info.RootUserID, now); err != nil {
			return err
		}
		if err := s.insertRecoveryEvent(txCtx, tx, recoveryEvent{
			ID: eventID, RootUserID: info.RootUserID,
			OperatorID: s.opts.Operator.ID, OperatorMachine: s.opts.Operator.Machine,
			Reason: reason, ActionsJSON: string(actionsJSON),
			PasswordReset: request.ResetPassword, MFAReset: request.ResetMFA,
			PasskeysRevoked:           request.RevokeLoginPasskeys,
			SessionsRevoked:           result.SessionsRevoked,
			FactorsDisabled:           result.FactorsDisabled,
			RecoveryCodeGroupsRevoked: result.RecoveryCodeGroupsRevoked,
			SecurityVersionAfter:      securityVersion, RequestID: requestID, CreatedAt: now,
		}); err != nil {
			return err
		}
		return s.fault(faultBeforeAuditDone)
	})
	if err != nil {
		return Result{}, mapRecoveryError(err)
	}
	s.opts.Logger.Info("root 本地应急恢复已完成",
		"event_id", eventID,
		"root_user_id", info.RootUserID,
		"security_version", result.SecurityVersionAfter,
		"sessions_revoked", result.SessionsRevoked,
		"factors_disabled", result.FactorsDisabled,
		"passkeys_revoked", result.PasskeysRevoked,
	)
	return result, nil
}

// validateRequest 校验恢复请求；ServiceStopped 必须是操作者显式确认。
func (s *Service) validateRequest(request Request) error {
	if !request.ServiceStopped {
		return ErrMaintenanceRequired
	}
	if !request.ResetPassword && !request.ResetMFA {
		return ErrNoAction
	}
	if request.RequestID != "" {
		if err := account.ValidateRequestID(request.RequestID); err != nil {
			return fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
		}
	}
	return nil
}

// ===== 事务内变更 =====

const upsertPasswordSQL = `INSERT INTO password_credentials(
user_id,hash_scheme,hash_version,password_hash,must_change,row_version,created_at_ms,updated_at_ms,changed_at_ms
) VALUES(?,'argon2id',19,?,0,1,?,?,?)
ON CONFLICT(user_id) DO UPDATE SET
hash_scheme=excluded.hash_scheme,
hash_version=excluded.hash_version,
password_hash=excluded.password_hash,
must_change=excluded.must_change,
row_version=password_credentials.row_version+1,
updated_at_ms=excluded.updated_at_ms,
changed_at_ms=excluded.changed_at_ms`

func (s *Service) applyPassword(ctx context.Context, tx audit.Tx, userID, passwordHash string, now time.Time) error {
	millis := now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, upsertPasswordSQL, userID, passwordHash, millis, millis, millis); err != nil {
		return fmt.Errorf("%w: 写入新密码失败", ErrStoreUnavailable)
	}
	return nil
}

// applyMFAAndRecoveryReset 仅在显式选择 MFA 重置时禁用邮件因素、TOTP 绑定、取消
// 待处理 MFA 挑战与恢复尝试；恢复代码**始终**作废（它们是绕过第二因素的通道，
// 应急恢复后不能继续可用）。未选择 MFA 重置时已有因素保持原状（Passkey 同理，
// 只有显式选择才撤销）。
func (s *Service) applyMFAAndRecoveryReset(ctx context.Context, tx audit.Tx,
	userID string, resetMFA bool, now time.Time) (int64, int64, error) {
	millis := now.UTC().UnixMilli()
	if resetMFA {
		factors, err := s.disableSecondFactors(ctx, tx, userID, millis)
		if err != nil {
			return 0, 0, err
		}
		groupResult, groupErr := tx.ExecContext(ctx,
			`UPDATE recovery_code_groups SET status='revoked',invalidated_at_ms=?
WHERE user_id=? AND status='active'`, millis, userID)
		if groupErr != nil {
			return 0, 0, fmt.Errorf("%w: 作废恢复代码失败", ErrStoreUnavailable)
		}
		groups, groupErr := groupResult.RowsAffected()
		if groupErr != nil {
			return 0, 0, fmt.Errorf("%w: 无法统计恢复代码作废结果", ErrStoreUnavailable)
		}
		return factors, groups, nil
	}
	groupResult, err := tx.ExecContext(ctx,
		`UPDATE recovery_code_groups SET status='revoked',invalidated_at_ms=?
WHERE user_id=? AND status='active'`, millis, userID)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: 作废恢复代码失败", ErrStoreUnavailable)
	}
	groups, err := groupResult.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("%w: 无法统计恢复代码作废结果", ErrStoreUnavailable)
	}
	return 0, groups, nil
}

// disableSecondFactors 禁用邮件因素、TOTP 绑定并取消待处理 MFA 挑战与恢复尝试。
func (s *Service) disableSecondFactors(ctx context.Context, tx audit.Tx,
	userID string, millis int64) (int64, error) {
	factors := int64(0)
	statements := []struct {
		query string
		args  []any
		count *int64
	}{
		{`UPDATE mfa_factors SET status='disabled',updated_at_ms=?
WHERE user_id=? AND status='active'`, []any{millis, userID}, &factors},
		{`UPDATE mfa_challenges SET state='cancelled',updated_at_ms=?
WHERE user_id=? AND state='pending'`, []any{millis, userID}, &factors},
		{`UPDATE totp_bindings SET status='disabled',updated_at_ms=?
WHERE user_id=? AND status IN('pending','active')`, []any{millis, userID}, &factors},
		{`UPDATE recovery_attempts SET status='cancelled',updated_at_ms=?,finished_at_ms=?
WHERE user_id=? AND status='pending_binding'`, []any{millis, millis, userID}, &factors},
	}
	for _, statement := range statements {
		result, err := tx.ExecContext(ctx, statement.query, statement.args...)
		if err != nil {
			return 0, fmt.Errorf("%w: 重置 MFA 因素失败", ErrStoreUnavailable)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("%w: 无法统计 MFA 重置结果", ErrStoreUnavailable)
		}
		*statement.count += affected
	}
	return factors, nil
}

func (s *Service) revokeSessions(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx,
		`UPDATE sessions SET revoked_at_ms=?,revoked_reason='root_emergency_recovery',
row_version=row_version+1 WHERE user_id=? AND revoked_at_ms IS NULL`,
		now.UTC().UnixMilli(), userID)
	if err != nil {
		return 0, fmt.Errorf("%w: 撤销 root 会话失败", ErrStoreUnavailable)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: 无法统计会话撤销结果", ErrStoreUnavailable)
	}
	return affected, nil
}

func (s *Service) revokePasskeys(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	millis := now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx,
		`UPDATE webauthn_credentials SET revoked_at_ms=?,revoked_reason='root_emergency_recovery',
updated_at_ms=?,version=version+1 WHERE user_id=? AND revoked_at_ms IS NULL`,
		millis, millis, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: 撤销 root Passkey 失败", ErrStoreUnavailable)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: 无法统计 Passkey 撤销结果", ErrStoreUnavailable)
	}
	return affected, nil
}

// revokeOneTimeCredentials 作废 root 名下所有仍可消费的一次性凭证（root 配置凭证、
// 邮箱变更/找回等）。安全版本递增不影响凭证消费，必须显式撤销，避免旧凭证在应急
// 恢复后仍可兑换。
func (s *Service) revokeOneTimeCredentials(ctx context.Context, tx audit.Tx, userID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE one_time_credentials SET revoked_at_ms=?
WHERE subject_id=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL`,
		now.UTC().UnixMilli(), userID); err != nil {
		return fmt.Errorf("%w: 作废一次性凭证失败", ErrStoreUnavailable)
	}
	return nil
}

func (s *Service) bumpSecurityVersion(ctx context.Context, tx audit.Tx, userID string, now time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx,
		`UPDATE users SET security_version=security_version+1,row_version=row_version+1,
updated_at_ms=? WHERE id=? AND is_root=1`, now.UTC().UnixMilli(), userID)
	if err != nil {
		return 0, fmt.Errorf("%w: 递增 root 安全版本失败", ErrStoreUnavailable)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%w: 无法确认安全版本更新", ErrStoreUnavailable)
	}
	if affected != 1 {
		return 0, fmt.Errorf("%w: root 账户未更新", ErrRootNotFound)
	}
	version, err := queryIntTx(ctx, tx, `SELECT security_version FROM users WHERE id=?`, userID)
	if err != nil {
		return 0, fmt.Errorf("%w: 无法读取新安全版本", ErrStoreUnavailable)
	}
	if version <= 0 {
		return 0, fmt.Errorf("%w: 新安全版本无效", ErrStoreUnavailable)
	}
	return version, nil
}

// forceReconfigureState 把 root 初始化状态复位为 setup_verified：已有正式密码但必须
// 重新绑定/确认强认证，不能留下 ready 或正常高权限会话状态。
func (s *Service) forceReconfigureState(ctx context.Context, tx audit.Tx, userID string, now time.Time) error {
	millis := now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx,
		`UPDATE root_initializations SET state='setup_verified',verified_at_ms=?,
ready_at_ms=NULL,setup_credential_id=NULL,updated_at_ms=?
WHERE root_user_id=?`, millis, millis, userID)
	if err != nil {
		return fmt.Errorf("%w: 复位 root 初始化状态失败", ErrStoreUnavailable)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: 无法确认 root 初始化状态", ErrStoreUnavailable)
	}
	if affected != 1 {
		return fmt.Errorf("%w: root 初始化记录未更新", ErrInvalidDatabase)
	}
	return nil
}

type recoveryActions struct {
	Password bool `json:"password_reset"`
	MFA      bool `json:"mfa_reset"`
	Passkeys bool `json:"passkeys_revoked"`
}

type recoveryEvent struct {
	ID                        string
	RootUserID                string
	OperatorID                string
	OperatorMachine           string
	Reason                    string
	ActionsJSON               string
	PasswordReset             bool
	MFAReset                  bool
	PasskeysRevoked           bool
	SessionsRevoked           int64
	FactorsDisabled           int64
	RecoveryCodeGroupsRevoked int64
	SecurityVersionAfter      int64
	RequestID                 string
	CreatedAt                 time.Time
}

const insertRecoveryEventSQL = `INSERT INTO root_recovery_events(
id,root_user_id,operator_id,operator_machine,reason,actions_json,password_reset,mfa_reset,
passkeys_revoked,sessions_revoked,factors_disabled,recovery_code_groups_revoked,
security_version_after,request_id,notification_state,notification_attempts,last_error_code,
created_at_ms,delivered_at_ms
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',0,'',?,NULL)`

func (s *Service) insertRecoveryEvent(ctx context.Context, tx audit.Tx, event recoveryEvent) error {
	if _, err := tx.ExecContext(ctx, insertRecoveryEventSQL,
		event.ID, event.RootUserID, event.OperatorID, event.OperatorMachine, event.Reason,
		event.ActionsJSON, boolInt(event.PasswordReset), boolInt(event.MFAReset),
		boolInt(event.PasskeysRevoked), event.SessionsRevoked, event.FactorsDisabled,
		event.RecoveryCodeGroupsRevoked, event.SecurityVersionAfter, event.RequestID,
		event.CreatedAt.UTC().UnixMilli()); err != nil {
		return fmt.Errorf("%w: 写入恢复记录失败", ErrStoreUnavailable)
	}
	return nil
}

// ===== 辅助 =====

func (s *Service) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func (s *Service) fault(stage string) error {
	if s.opts.TestOnlyFaultInjector == nil {
		return nil
	}
	return s.opts.TestOnlyFaultInjector(stage)
}

func (s *Service) newID(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := io.ReadFull(s.opts.Random, buffer); err != nil {
		return "", fmt.Errorf("%w: 安全随机源不可用", ErrOptionsInvalid)
	}
	return prefix + hex.EncodeToString(buffer), nil
}

func (s *Service) newRequestID() (string, error) {
	id, err := s.newID("rreq_")
	if err != nil {
		return "", err
	}
	return id, nil
}

// openRecoveryStore 以单连接、关闭 WAL 的方式打开已存在数据库：维护停机场景下不
// 引入 WAL 侧文件；任何打开失败都按无效实例处理（不改写数据库）。
func openRecoveryStore(ctx context.Context, path string) (*storagesqlite.Store, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, fmt.Errorf("%w: 数据库文件不存在或为空", ErrInvalidDatabase)
	}
	options := storagesqlite.DefaultOptions(path)
	options.WAL = false
	options.MaxOpenConns = 1
	options.MaxIdleConns = 1
	store, err := storagesqlite.Open(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开数据库", ErrInvalidDatabase)
	}
	return store, nil
}

func mapRecoveryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, audit.ErrAuditUnavailable):
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	case errors.Is(err, audit.ErrInvalidEvent):
		return fmt.Errorf("%w: 审计事件无效", ErrOptionsInvalid)
	case errors.Is(err, ErrOptionsInvalid), errors.Is(err, ErrInvalidRequest),
		errors.Is(err, ErrMaintenanceRequired), errors.Is(err, ErrLocked),
		errors.Is(err, ErrInvalidDatabase), errors.Is(err, ErrRootNotFound),
		errors.Is(err, ErrRootNotEligible), errors.Is(err, ErrConfirmationDeclined),
		errors.Is(err, ErrPasswordPolicy), errors.Is(err, ErrNoAction),
		errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrAuditUnavailable):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// zeroBytes 尽力清零敏感字节切片；调用方不得在清零后再使用该切片。
func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// truncateRunes 按 Unicode 码点截断并追加省略号，避免拆断多字节字符。
func truncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func isNilInterface(value any) bool {
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
