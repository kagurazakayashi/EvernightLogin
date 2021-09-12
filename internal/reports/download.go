package reports

// 本文件实现步骤 79 的短期下载令牌：页面只能先取得绑定“报告 ID + 格式 + 调用者 +
// 到期时间”的一次性令牌，再用它兑换受控产物；令牌兑换时重新执行完整下载鉴权，
// 到期/使用/失权/清理后都不再可用。它不是永久分享链接，也不写入 URL 之外的存储。
//
// 安全不变量：
//   - 令牌随机生成、只保存摘要，签发与兑换都必须来自可信调用者身份；
//   - 绑定签发调用者：其他人即使拿到令牌也不能兑换；
//   - 一次性：兑换动作先原子消费令牌，再执行鉴权；失败也不回滚令牌（防重放）；
//   - 有界有效期（默认 5 分钟，硬上限 15 分钟）与有界数量，过期令牌被修剪；
//   - 兑换复用 OpenFile 的当前权限、数据范围、产物摘要与审计检查，不另建旁路。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// DownloadTicket 是签发给页面的短期下载令牌元数据（令牌本身只返回一次）。
type DownloadTicket struct {
	// Token 是一次性令牌原文；只返回给签发时的调用者，不写日志/审计。
	Token string
	// ReportID/Format 是令牌绑定的目标，兑换时不得改变。
	ReportID string
	Format   Format
	// IssuedAt/ExpiresAt 是签发与到期时刻；页面必须展示有效期。
	IssuedAt  time.Time
	ExpiresAt time.Time
	// TTL 是本次令牌有效期，供页面显示“几分钟内有效”。
	TTL time.Duration
}

// downloadTicketEntry 是进程内令牌条目；键为令牌摘要（不保存原文）。
type downloadTicketEntry struct {
	reportID  string
	format    Format
	actor     audit.Actor
	expiresAt time.Time
}

// downloadTickets 是并发安全的短期令牌表：有界数量、过期自动修剪。
type downloadTickets struct {
	mu      sync.Mutex
	entries map[string]downloadTicketEntry
	ttl     time.Duration
	now     func() time.Time
	random  io.Reader
}

// newDownloadTickets 构造令牌表；调用方已校验 ttl 范围。
func newDownloadTickets(ttl time.Duration, now func() time.Time,
	random io.Reader) *downloadTickets {
	return &downloadTickets{entries: make(map[string]downloadTicketEntry), ttl: ttl,
		now: now, random: random}
}

// ticketDigest 返回令牌摘要（表键），不保留原文。
func ticketDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// validDownloadToken 校验令牌原文格式：64 位小写十六进制（32 字节）。
func validDownloadToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// pruneLocked 修剪过期条目，直到不超过上限；调用方必须持有 mu。
func (t *downloadTickets) pruneLocked(now time.Time) {
	removed := 0
	for key, entry := range t.entries {
		if !now.Before(entry.expiresAt) {
			delete(t.entries, key)
			removed++
			if removed >= cleanupTicketPruneBatch {
				return
			}
		}
	}
	if len(t.entries) < MaxDownloadTickets {
		return
	}
	// 仍超上限时按到期时间删除最早的条目，保持有界内存；被删令牌只能重新申请。
	for removed < cleanupTicketPruneBatch && len(t.entries) >= MaxDownloadTickets {
		oldestKey, oldestAt := "", time.Time{}
		for key, entry := range t.entries {
			if oldestAt.IsZero() || entry.expiresAt.Before(oldestAt) {
				oldestKey, oldestAt = key, entry.expiresAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(t.entries, oldestKey)
		removed++
	}
}

// issue 生成并保存一个绑定调用者的新令牌。
func (t *downloadTickets) issue(reportID string, format Format,
	actor audit.Actor) (DownloadTicket, error) {
	buffer := make([]byte, 32)
	if _, err := io.ReadFull(t.random, buffer); err != nil {
		return DownloadTicket{}, fmt.Errorf("%w: 无法生成下载令牌", ErrStoreUnavailable)
	}
	token := hex.EncodeToString(buffer)
	now := t.now().UTC().Truncate(time.Millisecond)
	expiresAt := now.Add(t.ttl)
	t.mu.Lock()
	t.pruneLocked(now)
	t.entries[ticketDigest(token)] = downloadTicketEntry{
		reportID: reportID, format: format, actor: actor, expiresAt: expiresAt}
	t.mu.Unlock()
	return DownloadTicket{Token: token, ReportID: reportID, Format: format,
		IssuedAt: now, ExpiresAt: expiresAt, TTL: t.ttl}, nil
}

// consume 原子消费令牌：成功返回条目并删除；不存在/过期/调用者不符返回错误。
func (t *downloadTickets) consume(token string, actor audit.Actor) (downloadTicketEntry, error) {
	if !validDownloadToken(token) {
		return downloadTicketEntry{}, ErrTicketInvalid
	}
	key := ticketDigest(token)
	now := t.now().UTC().Truncate(time.Millisecond)
	t.mu.Lock()
	entry, found := t.entries[key]
	if !found {
		t.mu.Unlock()
		return downloadTicketEntry{}, ErrTicketInvalid
	}
	if entry.actor != actor {
		// 不消费他人的令牌：避免第三方用猜测/泄露的令牌让合法持有者失效。
		t.mu.Unlock()
		return downloadTicketEntry{}, ErrTicketAccessDenied
	}
	if !now.Before(entry.expiresAt) {
		delete(t.entries, key)
		t.mu.Unlock()
		return downloadTicketEntry{}, ErrTicketExpired
	}
	delete(t.entries, key)
	t.mu.Unlock()
	return entry, nil
}

// DownloadTicketTTL 返回当前配置的下载令牌有效期（页面展示用）。
func (s *Service) DownloadTicketTTL() time.Duration {
	if s.tickets == nil {
		return DefaultDownloadTicketTTL
	}
	return s.tickets.ttl
}

// IssueDownloadTicket 为指定报告格式签发一次性短期下载令牌。签发前执行与下载
// 相同的当前鉴权与产物校验；签发动作写审计，审计不可用时拒绝签发（fail-closed）。
// 令牌只返回一次，不能作为永久分享地址。
func (s *Service) IssueDownloadTicket(ctx context.Context, caller account.Caller,
	reportID string, format Format) (DownloadTicket, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous {
		return DownloadTicket{}, ErrAccessDenied
	}
	resolved, err := s.resolveArtifact(ctx, caller, reportID, format)
	if err != nil {
		if isDownloadDenied(err) {
			return DownloadTicket{}, fmt.Errorf("%w: %w", ErrTicketNotAllowed, err)
		}
		return DownloadTicket{}, err
	}
	_ = resolved
	ticket, err := s.tickets.issue(reportID, format, actor)
	if err != nil {
		return DownloadTicket{}, err
	}
	event := audit.Event{
		Actor: actor, AppID: appIDForScope(resolved.scopeID),
		Action: ActionDownloadTicketIssue, Target: audit.Target{Type: "report", ID: reportID},
		Outcome: audit.OutcomeSuccess, RequestID: resolved.requestID,
		Changes: []audit.FieldChange{{Field: "format", After: string(format)},
			{Field: "ticket_expires_at", After: ticket.ExpiresAt.Format(time.RFC3339)}},
	}
	if err := s.opts.Audit.Record(ctx, event); err != nil {
		return DownloadTicket{}, fmt.Errorf("%w: 下载令牌签发审计写入失败", ErrAuditUnavailable)
	}
	return ticket, nil
}

// isDownloadDenied 判断错误是否属于“当前不允许下载”的拒绝（失权/过期/清理/冲突），
// 用于给页面稳定的令牌状态码；存储不可用等错误不伪装成权限拒绝。
func isDownloadDenied(err error) bool {
	return errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrConflict) || errors.Is(err, ErrArtifactUnsafe)
}

// RedeemDownloadTicket 兑换一次性短期下载令牌：先原子消费令牌，再执行完整下载
// 鉴权并写下载审计。令牌在兑换前已过期或被使用都按失败处理；兑换失败也不会
// 退回令牌（一次性语义），调用方必须重新申请。
func (s *Service) RedeemDownloadTicket(ctx context.Context, caller account.Caller,
	token string) (ArtifactFile, error) {
	actor := caller.Actor()
	if err := actor.Validate(); err != nil || actor.Type == audit.ActorAnonymous {
		return ArtifactFile{}, ErrAccessDenied
	}
	entry, err := s.tickets.consume(token, actor)
	if err != nil {
		s.recordFailure(ctx, actor, ActionDownloadTicketDeny, "",
			"ticket_redeem_denied", CodeReportAccessDenied, "", "")
		return ArtifactFile{}, err
	}
	return s.OpenFile(ctx, caller, entry.reportID, entry.format)
}
