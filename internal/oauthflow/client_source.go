package oauthflow

import (
	"context"
	"fmt"
	"reflect"

	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
)

// OAuthClientReader 是读取 oauthclient 登记配置所需的最小只读接口；生产实现为
// internal/oauthclient.Store（同一 GetClient 方法签名）。
type OAuthClientReader interface {
	GetClient(ctx context.Context, clientID string) (oauthclient.ClientRecord, bool, error)
}

// OAuthClientSource 把 internal/oauthclient 登记配置适配为授权流程的 ClientSource。
// 只读取客户端安全设置与所属应用状态，不读取 secret/证书材料。
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
func (s *OAuthClientSource) LoadClient(ctx context.Context, clientID string) (ClientInfo, bool, error) {
	record, found, err := s.reader.GetClient(ctx, clientID)
	if err != nil {
		return ClientInfo{}, false, ErrStoreUnavailable
	}
	if !found {
		return ClientInfo{}, false, nil
	}
	return ClientInfo{
		ClientID:     record.ClientID,
		ClientType:   record.ClientType,
		AppStatus:    record.AppStatus,
		GrantTypes:   append([]oauthclient.GrantType(nil), record.GrantTypes...),
		RedirectURIs: append([]string(nil), record.RedirectURIs...),
		Scopes:       append([]string(nil), record.Scopes...),
		Audiences:    append([]string(nil), record.Audiences...),
		RequirePKCE:  record.RequirePKCE,
	}, true, nil
}

// 编译期断言：生产适配器实现 ClientSource。
var _ ClientSource = (*OAuthClientSource)(nil)

// isNilInterface 检测 nil 接口与 typed nil，避免把 typed nil 当成可用依赖。
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
