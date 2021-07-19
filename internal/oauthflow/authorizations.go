package oauthflow

import (
	"context"
	"sort"
	"time"
)

const (
	authorizationListDefaultPageSize = 20
	authorizationListMaxPageSize     = 50
)

// AuthorizationListOptions 是用户自助“已授权应用”列表的分页参数；页码从 1 开始。
type AuthorizationListOptions struct {
	Page     int
	PageSize int
}

// AuthorizationSummary 是一条本人已批准授权的公开摘要：不含授权码、Token、state、
// PKCE 或任何秘密；应用展示名由页面适配层受控 Join。
type AuthorizationSummary struct {
	AuthorizationID string
	ClientID        string
	Scopes          []string
	Audiences       []string
	Status          string
	ApprovedAt      time.Time
	ExpiresAt       time.Time
	// ActiveRefreshFamilies/RevokedRefreshFamilies 是该授权下的刷新令牌族计数；
	// 未签发刷新令牌时为 0（不推断“永久授权”）。
	ActiveRefreshFamilies  int
	RevokedRefreshFamilies int
	OnlineRevoked          bool
}

// AuthorizationPage 是一页已授权应用摘要；分页有界，HasMore 由真实总数与已消费数
// 决定，不伪造末页。
type AuthorizationPage struct {
	Authorizations []AuthorizationSummary
	Page           int
	PageSize       int
	Total          int64
	HasMore        bool
}

// ListUserAuthorizations 列出调用方本人已批准、未过期、未被在线撤销的授权确认请求。
//
// 安全边界：用户身份只来自服务端会话秘密（不接收客户端自报 userID）；只返回本人
// 记录；分页大小有硬上限；每条记录只含 Scope/audience/时间/刷新族计数，不含授权码、
// Token、state 或 PKCE；在线撤销标记按（用户,客户端）读取并用于排除已撤销授权。
// 撤回本身仍需页面层按敏感策略完成再次认证后调用 RevokeAuthorization。
func (s *Service) ListUserAuthorizations(ctx context.Context, sessionSecret string,
	options AuthorizationListOptions) (AuthorizationPage, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return AuthorizationPage{}, err
	}
	userSession, err := s.opts.Sessions.Validate(ctx, sessionSecret)
	if err != nil || !userSession.IsNormal() {
		return AuthorizationPage{}, oauthAccessDeniedRedirect("需要登录后查看已授权应用", "", "")
	}
	page := options.Page
	if page < 1 {
		page = 1
	}
	pageSize := options.PageSize
	if pageSize <= 0 {
		pageSize = authorizationListDefaultPageSize
	}
	if pageSize > authorizationListMaxPageSize {
		return AuthorizationPage{}, oauthInvalidRequest("分页大小超过上限")
	}
	now := s.now()
	records, total, err := s.opts.Store.ListApprovedAuthorizationRequests(ctx,
		userSession.UserID, now, (page-1)*pageSize, pageSize)
	if err != nil {
		return AuthorizationPage{}, oauthTemporarilyUnavailable()
	}
	summaries := make([]AuthorizationSummary, 0, len(records))
	for _, record := range records {
		if record.UserID != userSession.UserID {
			continue
		}
		revokedAt, revoked, revokeErr := s.opts.Store.ClientUserRevocation(ctx,
			record.UserID, record.ClientID)
		if revokeErr != nil {
			return AuthorizationPage{}, oauthTemporarilyUnavailable()
		}
		if revoked && !revokedAt.Before(record.DecidedAt) {
			// 在线撤销后该应用授权不再出现在“已授权”列表。
			continue
		}
		families, familyErr := s.opts.Store.ListRefreshFamilies(ctx, record.UserID,
			record.ClientID, record.ID)
		if familyErr != nil {
			return AuthorizationPage{}, oauthTemporarilyUnavailable()
		}
		active, revokedFamilies := 0, 0
		for _, family := range families {
			if family.RevokedAt.IsZero() && now.Before(family.AbsoluteExpiresAt) {
				active++
			} else {
				revokedFamilies++
			}
		}
		summary := AuthorizationSummary{AuthorizationID: record.ID,
			ClientID: record.ClientID, Scopes: append([]string(nil), record.Scopes...),
			Audiences: append([]string(nil), record.Audiences...), Status: record.Status,
			ApprovedAt: record.DecidedAt, ExpiresAt: record.ExpiresAt,
			ActiveRefreshFamilies: active, RevokedRefreshFamilies: revokedFamilies}
		summaries = append(summaries, summary)
	}
	sort.SliceStable(summaries, func(left, right int) bool {
		return summaries[left].ApprovedAt.After(summaries[right].ApprovedAt)
	})
	pageStart := int64((page - 1) * pageSize)
	return AuthorizationPage{Authorizations: summaries, Page: page, PageSize: pageSize,
		Total: total, HasMore: pageStart+int64(len(summaries)) < total}, nil
}
