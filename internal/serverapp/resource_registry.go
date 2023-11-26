package serverapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	oauthclientsqlite "github.com/kagurazakayashi/EvernightLogin/internal/oauthclient/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// resourceServiceEntry 是受信资源服务登记项：OAuth confidential 客户端认证材料 +
// 一个可用 audience；applicationID 与 client_id 一一对应（现有模型）。
type resourceServiceEntry struct {
	ServiceID string
	ClientID  string
	Audience  string
}

// resourceRegistry 是启动期只读登记表；不信任请求自述的 app_id/audience。
type resourceRegistry struct {
	byClient map[string][]resourceServiceEntry
}

// loadResourceRegistry 校验配置登记与真实 OAuth 客户端/应用状态。
func loadResourceRegistry(ctx context.Context, deps Deps) (*resourceRegistry, error) {
	entries := deps.Config.Protocol.ResourceServices
	if len(entries) == 0 {
		return &resourceRegistry{byClient: map[string][]resourceServiceEntry{}}, nil
	}
	clientStore, err := oauthclientsqlite.New(deps.Store)
	if err != nil {
		return nil, fmt.Errorf("构造资源服务客户端存储失败: %w", err)
	}
	registry := &resourceRegistry{byClient: make(map[string][]resourceServiceEntry, len(entries))}
	for _, entry := range entries {
		clientID := strings.TrimSpace(entry.ClientID)
		audience := strings.TrimSpace(entry.Audience)
		record, found, err := clientStore.GetClient(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("读取资源服务客户端失败: %w", err)
		}
		if !found {
			return nil, fmt.Errorf("资源服务 client_id %q 未登记为 OAuth 客户端", clientID)
		}
		if record.ClientType != oauthclient.ClientTypeConfidential {
			return nil, fmt.Errorf("资源服务 client_id %q 必须是 confidential 客户端（需要认证材料）", clientID)
		}
		if record.AppStatus != string(app.StatusActive) {
			return nil, fmt.Errorf("资源服务 client_id %q 所属应用不是 active 状态", clientID)
		}
		allowed := false
		for _, candidate := range record.Audiences {
			if candidate == audience {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("资源服务 audience %q 未在 client_id %q 的 Audiences 中登记", audience, clientID)
		}
		registry.byClient[clientID] = append(registry.byClient[clientID], resourceServiceEntry{
			ServiceID: strings.TrimSpace(entry.ServiceID), ClientID: clientID, Audience: audience,
		})
	}
	return registry, nil
}

// entriesForClient 返回某客户端可用的资源身份（可能多个 audience）。
func (r *resourceRegistry) entriesForClient(clientID string) []resourceServiceEntry {
	if r == nil {
		return nil
	}
	return r.byClient[clientID]
}

// lookupByServiceID 按启动配置中唯一的 service_id 查询资源服务登记。公开 Go 查询
// 入口只接受该受信标识，不信任调用方自述 application_id/audience。
func (r *resourceRegistry) lookupByServiceID(serviceID string) (resourceServiceEntry, error) {
	if r == nil {
		return resourceServiceEntry{}, fmt.Errorf("资源服务登记未装配")
	}
	serviceID = strings.TrimSpace(serviceID)
	if serviceID == "" {
		return resourceServiceEntry{}, fmt.Errorf("资源服务标识为空")
	}
	for _, entries := range r.byClient {
		for _, entry := range entries {
			if entry.ServiceID == serviceID {
				return entry, nil
			}
		}
	}
	return resourceServiceEntry{}, fmt.Errorf("资源服务未登记")
}

// resolve 选择本次请求的资源身份：未指定 audience 时仅允许唯一登记；指定时必须
// 命中该客户端的登记白名单。
func (r *resourceRegistry) resolve(clientID, audience string) (resourceServiceEntry, error) {
	entries := r.entriesForClient(clientID)
	if len(entries) == 0 {
		return resourceServiceEntry{}, fmt.Errorf("调用客户端未登记为受信资源服务")
	}
	audience = strings.TrimSpace(audience)
	if audience == "" {
		if len(entries) != 1 {
			return resourceServiceEntry{}, fmt.Errorf("该资源服务登记了多个 audience，请求必须显式指定 audience")
		}
		return entries[0], nil
	}
	for _, entry := range entries {
		if entry.Audience == audience {
			return entry, nil
		}
	}
	return resourceServiceEntry{}, fmt.Errorf("请求的 audience 不属于该资源服务")
}

// resourceServiceFor 把登记项转换为 tokenauthz 可信身份。
func resourceServiceFor(entry resourceServiceEntry) (resourceIdentity, error) {
	return newResourceIdentity(entry)
}

// resourceIdentity 是 serverapp 内部对 tokenauthz.ResourceService 的构造结果包装，
// 避免在公开签名中泄露 internal 类型。
type resourceIdentity struct {
	serviceID     string
	applicationID string
	audience      string
}

func newResourceIdentity(entry resourceServiceEntry) (resourceIdentity, error) {
	if entry.ServiceID == "" || entry.ClientID == "" || entry.Audience == "" {
		return resourceIdentity{}, fmt.Errorf("资源服务登记不完整")
	}
	return resourceIdentity{serviceID: entry.ServiceID, applicationID: entry.ClientID,
		audience: entry.Audience}, nil
}

var _ = login.CodeConfigInvalid

// resourceInspectAuthorizer 用资源服务登记实现 RFC 7662 的 audience 授权：
// 只有登记过的 (resourceServerClientID, audience) 才被允许查看令牌元数据。
type resourceInspectAuthorizer struct{ registry *resourceRegistry }

// AuthorizeInspection 实现 oauthflow.InspectAuthorizer。
func (a resourceInspectAuthorizer) AuthorizeInspection(_ context.Context,
	resourceServerClientID, audience string) (oauthflow.InspectPermission, error) {
	if a.registry == nil {
		return oauthflow.InspectPermission{Allowed: false}, nil
	}
	entry, err := a.registry.resolve(resourceServerClientID, audience)
	if err != nil || entry.ClientID == "" {
		return oauthflow.InspectPermission{Allowed: false}, nil
	}
	// 不向资源服务披露 sub：跨应用/跨资源的 subject 关联由联合权限判定
	// （tokenauthz）按受信身份处理，标准 introspection 只返回令牌状态元数据。
	return oauthflow.InspectPermission{Allowed: true, ShowSubject: false}, nil
}

// resourceInspectClientAuthorizer 限制刷新令牌元数据查询：资源服务只能查看与自身
// 登记应用同一客户端（client_id=application_id）的刷新令牌族。
type resourceInspectClientAuthorizer struct{ registry *resourceRegistry }

// AuthorizeClientInspection 实现 oauthflow.InspectClientAuthorizer。
func (a resourceInspectClientAuthorizer) AuthorizeClientInspection(_ context.Context,
	resourceServerClientID, clientID, audience string) error {
	if a.registry == nil {
		return fmt.Errorf("未配置资源服务登记")
	}
	entry, err := a.registry.resolve(resourceServerClientID, audience)
	if err != nil {
		return err
	}
	if entry.ClientID != clientID {
		return fmt.Errorf("资源服务不能查看其他客户端的刷新令牌")
	}
	return nil
}
