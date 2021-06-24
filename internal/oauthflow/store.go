package oauthflow

import (
	"context"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// AuthorizationRequestRecord 是一次授权确认请求的持久化记录。它不包含会话秘密、
// 授权码明文或令牌；state 是不透明回传值（不参与授权判断），nonce 供后续 OIDC。
type AuthorizationRequestRecord struct {
	ID                  string
	UserID              string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scopes              []string
	Audiences           []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	SecurityVersion     int64
	// AuthTime 是授权确认时会话的真实登录时间；AuthMethods 是当时真实完成的认证
	// 方法（稳定标识），供 ID Token 的 auth_time/amr/acr 使用，不能事后伪造。
	AuthTime    time.Time
	AuthMethods []string
	Status      string
	RequestID   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DecidedAt   time.Time
}

// AuthorizationCodeRecord 是授权码记录；只保存摘要 CodeSHA256，不保存明文。兑换时
// 逐项比对绑定字段，consumed_at_ms 条件更新保证一次性与并发单赢家。
type AuthorizationCodeRecord struct {
	ID                  string
	CodeSHA256          [32]byte
	RequestID           string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	Audiences           []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	SecurityVersion     int64
	// AuthTime/AuthMethods 来自授权确认时的会话真实认证事实。
	AuthTime    time.Time
	AuthMethods []string
	RequestRef  string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	ConsumedAt  time.Time
	ReplayedAt  time.Time
}

// UserState 是授权/兑换时重新读取的账户状态快照。
type UserState struct {
	UserID          string
	Status          string
	IsRoot          bool
	SecurityVersion int64
}

// Active 报告账户是否可继续使用（仅 active）。
func (u UserState) Active() bool { return u.Status == "active" }

// SessionSnapshot 是授权码兑换时校验的会话快照（不含秘密）：授权码绑定的会话必须
// 仍然有效、属于同一用户、安全版本一致且未被撤销。
type SessionSnapshot struct {
	ID              string
	UserID          string
	AppID           string
	Kind            string
	SecurityVersion int64
	// AuthTime 是会话建立（真实认证完成）时间；AuthMethods 是当时完成的方法。
	AuthTime          time.Time
	AuthMethods       []string
	StrongAuthAt      time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         time.Time
}

// ActiveAt 报告会话在 now 时刻是否仍有效（服务端状态、未撤销、未到期、普通会话）。
func (s SessionSnapshot) ActiveAt(now time.Time) bool {
	return s.RevokedAt.IsZero() && s.Kind == "normal" &&
		s.ID != "" && s.UserID != "" &&
		now.Before(s.IdleExpiresAt) && now.Before(s.AbsoluteExpiresAt)
}

// RefreshFamilyRecord 是刷新令牌族：绑定客户端、用户主体、授权请求、Scope、
// 资源 audience 与用户安全版本快照；绝对有效期固定在族上。
type RefreshFamilyRecord struct {
	ID                string
	ClientID          string
	SubjectUserID     string
	AuthorizationID   string
	Scopes            []string
	Audiences         []string
	SecurityVersion   int64
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
	IdleTimeout       time.Duration
	RevokedAt         time.Time
	RevokeReason      string
}

// ActiveAt 报告族在 now 时刻是否仍有效（未撤销、未超绝对有效期）。
func (f RefreshFamilyRecord) ActiveAt(now time.Time) bool {
	return f.RevokedAt.IsZero() && now.Before(f.AbsoluteExpiresAt)
}

// RefreshTokenRecord 是刷新令牌持久化记录：只保存 SHA-256 验证摘要，不保存明文。
type RefreshTokenRecord struct {
	ID            string
	FamilyID      string
	TokenSHA256   [32]byte
	Status        string
	IssuedAt      time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	UsedAt        time.Time
	RevokedAt     time.Time
	RevokeReason  string
	ReplacedByID  string
	RequestID     string
}

// RefreshStatusActive 是刷新令牌唯一可用于轮换的状态。
const RefreshStatusActive = "active"

// Store 是 OAuth 授权确认与授权码的持久化契约，由 internal/oauthflow/sqlite 提供
// SQLite 实现。变更类方法必须在调用方审计事务内执行，失败整体回滚。
type Store interface {
	// CreateAuthorizationRequestTx 在审计事务内创建 pending 确认请求。
	CreateAuthorizationRequestTx(ctx context.Context, tx audit.Tx, request AuthorizationRequestRecord) error
	// GetAuthorizationRequest 读取确认请求；不存在返回 found=false。
	GetAuthorizationRequest(ctx context.Context, requestID string) (AuthorizationRequestRecord, bool, error)
	// DecideAuthorizationRequestTx 条件把 pending 请求迁移为 approved/denied；
	// 已决定/不存在/已过期时返回 false（并发决定只有一方成功）。
	DecideAuthorizationRequestTx(ctx context.Context, tx audit.Tx, requestID, status string,
		now time.Time) (bool, error)
	// CreateAuthorizationCodeTx 在审计事务内插入授权码摘要记录（唯一摘要约束兜底）。
	CreateAuthorizationCodeTx(ctx context.Context, tx audit.Tx, code AuthorizationCodeRecord) error
	// GetAuthorizationCodeByHash 按摘要读取授权码记录。
	GetAuthorizationCodeByHash(ctx context.Context, digest [32]byte) (AuthorizationCodeRecord, bool, error)
	// ConsumeAuthorizationCodeTx 条件消费未过期未消费的授权码；返回是否赢家。
	ConsumeAuthorizationCodeTx(ctx context.Context, tx audit.Tx, codeID string, now time.Time) (bool, error)
	// MarkAuthorizationCodeReplayed 记录重复兑换探测（不影响已签发令牌）。
	MarkAuthorizationCodeReplayed(ctx context.Context, codeID string, now time.Time) error

	// UserState 读取账户状态快照（授权确认与兑换前复核用户仍 active）。
	UserState(ctx context.Context, userID string) (UserState, bool, error)
	// MembershipActive 报告用户是否为该应用的 active 成员。
	MembershipActive(ctx context.Context, userID, appID string) (bool, error)
	// SessionSnapshot 读取授权码绑定会话的服务端快照。
	SessionSnapshot(ctx context.Context, sessionID string) (SessionSnapshot, bool, error)

	// CreateRefreshFamilyTx 在审计事务内创建刷新令牌族与首个刷新令牌。
	CreateRefreshFamilyTx(ctx context.Context, tx audit.Tx, family RefreshFamilyRecord,
		token RefreshTokenRecord) error
	// GetRefreshTokenByHash 按摘要读取刷新令牌记录。
	GetRefreshTokenByHash(ctx context.Context, digest [32]byte) (RefreshTokenRecord, bool, error)
	// GetRefreshFamily 按 ID 读取刷新令牌族。
	GetRefreshFamily(ctx context.Context, familyID string) (RefreshFamilyRecord, bool, error)
	// ConsumeRefreshTokenTx 条件把 active 刷新令牌消费为 used（匹配未过期）；
	// 并发/重放只有一方成功。
	ConsumeRefreshTokenTx(ctx context.Context, tx audit.Tx, tokenID string, now time.Time) (bool, error)
	// InsertRefreshTokenTx 在审计事务内插入轮换产生的新刷新令牌。
	InsertRefreshTokenTx(ctx context.Context, tx audit.Tx, token RefreshTokenRecord) error
	// ExpireRefreshTokenTx 条件把 active 但空闲到期的刷新令牌标记为 expired。
	ExpireRefreshTokenTx(ctx context.Context, tx audit.Tx, tokenID string, now time.Time) (bool, error)
	// RevokeRefreshFamilyTx 撤销整族：族置 revoked 并撤销其全部 active 令牌；
	// 返回被撤销令牌数（重放检测/账户失效遏制）。
	RevokeRefreshFamilyTx(ctx context.Context, tx audit.Tx, familyID, reason string, now time.Time) (int64, error)
}
