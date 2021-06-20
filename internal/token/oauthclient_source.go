package token

import (
	"context"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// OAuthClientReader 是令牌服务读取客户端登记配置所需的最小只读接口；生产实现为
// internal/oauthclient.Store（同一方法签名），测试可用轻量替身。
type OAuthClientReader interface {
	GetClient(ctx context.Context, clientID string) (oauthclient.ClientRecord, bool, error)
}

// OAuthClientSource 把 internal/oauthclient 的登记配置适配为令牌服务的 ClientSource。
//
// 只读取客户端安全设置（授权类型/Scope/audience/应用状态），不读取客户端密钥或
// 证书秘密；app 状态非 active 时映射为不可用，避免向停用应用签发令牌。
type OAuthClientSource struct {
	reader OAuthClientReader
}

// NewOAuthClientSource 构造客户端来源适配器；reader 为空（含 typed-nil）时拒绝。
func NewOAuthClientSource(reader OAuthClientReader) (*OAuthClientSource, error) {
	if isNilInterface(reader) {
		return nil, fmt.Errorf("%w: OAuth 客户端读取器为空", ErrOptionsInvalid)
	}
	return &OAuthClientSource{reader: reader}, nil
}

// LoadClient 实现 ClientSource。
func (s *OAuthClientSource) LoadClient(ctx context.Context, clientID string) (ClientInfo, error) {
	record, found, err := s.reader.GetClient(ctx, clientID)
	if err != nil {
		return ClientInfo{}, ErrStoreUnavailable
	}
	if !found {
		return ClientInfo{}, ErrClientNotFound
	}
	grantTypes := make([]string, 0, len(record.GrantTypes))
	for _, grant := range record.GrantTypes {
		grantTypes = append(grantTypes, string(grant))
	}
	info := ClientInfo{
		ClientID:      record.ClientID,
		ApplicationID: record.ClientID,
		ClientType:    string(record.ClientType),
		AppActive:     record.AppStatus == "active",
		GrantTypes:    grantTypes,
		Scopes:        append([]string(nil), record.Scopes...),
		Audiences:     append([]string(nil), record.Audiences...),
	}
	return info, nil
}

// 编译期断言：OAuthClientSource 实现 ClientSource。
var _ ClientSource = (*OAuthClientSource)(nil)
