package serverapp

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	accountsqlite "github.com/kagurazakayashi/EvernightLogin/internal/account/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	appsqlite "github.com/kagurazakayashi/EvernightLogin/internal/app/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
	"github.com/kagurazakayashi/EvernightLogin/internal/token"
)

// tokenStateChecker 实现 oauthflow.TokenStateChecker：在签名/撤销验证之后再核对
// 当前账户、应用与成员状态，避免“签名有效但当前已不可用”的令牌被报告 active。
type tokenStateChecker struct {
	accountStore *accountsqlite.Store
	appStore     *appsqlite.Store
	clientStore  *oauthclientsqlite.Store
}

var _ oauthflow.TokenStateChecker = (*tokenStateChecker)(nil)

// newTokenStateChecker 构造当前状态复核器。
func newTokenStateChecker(deps Deps) (*tokenStateChecker, error) {
	accountStore, err := accountsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造令牌状态账户存储失败: %w", err)
	}
	appStore, err := appsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造令牌状态应用存储失败: %w", err)
	}
	clientStore, err := oauthclientsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造令牌状态客户端存储失败: %w", err)
	}
	return &tokenStateChecker{accountStore: accountStore, appStore: appStore, clientStore: clientStore}, nil
}

// CheckAccessTokenState 复核用户/服务主体、客户端/应用与（用户令牌的）成员状态。
func (c *tokenStateChecker) CheckAccessTokenState(ctx context.Context,
	claims token.AccessClaims) (bool, string, error) {
	record, found, err := c.clientStore.GetClient(ctx, claims.ClientID)
	if err != nil {
		return false, "", err
	}
	if !found || record.AppStatus != string(app.StatusActive) {
		return false, "client_or_app_inactive", nil
	}
	application, err := c.appStore.GetApplication(ctx, claims.ClientID)
	if err != nil {
		if err == app.ErrApplicationNotFound {
			return false, "application_not_found", nil
		}
		return false, "", err
	}
	if application.Status != app.StatusActive {
		return false, "application_inactive", nil
	}
	subjectType := claims.SubjectType
	if subjectType == "" {
		subjectType = "user"
	}
	if subjectType == "service" {
		return true, "", nil
	}
	subject := claims.Subject
	if subject == "" {
		return false, "missing_subject", nil
	}
	state, err := c.accountStore.GetUserState(ctx, subject)
	if err != nil {
		if err == account.ErrUserNotFound {
			return false, "user_not_found", nil
		}
		return false, "", err
	}
	if state.User.Status != account.StatusActive {
		return false, "user_inactive", nil
	}
	membership, err := c.appStore.GetMembership(ctx, claims.ClientID, subject)
	if err != nil {
		if err == app.ErrMemberNotFound {
			return false, "membership_missing", nil
		}
		return false, "", err
	}
	if membership.Status != app.MembershipActive {
		return false, "membership_disabled", nil
	}
	return true, "", nil
}

// CheckRefreshTokenState 复核刷新令牌所属客户端的应用状态。
func (c *tokenStateChecker) CheckRefreshTokenState(ctx context.Context,
	clientID string) (bool, string, error) {
	record, found, err := c.clientStore.GetClient(ctx, clientID)
	if err != nil {
		return false, "", err
	}
	if !found || record.AppStatus != string(app.StatusActive) {
		return false, "client_or_app_inactive", nil
	}
	return true, "", nil
}

var _ = oauthclient.ClientTypeConfidential
