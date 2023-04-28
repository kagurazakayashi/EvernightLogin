package serverapp

// 步骤 147：业务托管管理 API（/api/managed/v1）的生产装配。
//
// 与 internal/adminapi（管理强会话）严格分离：本 API 使用用户普通会话 Bearer 或
// 应用客户端 secret/证书；默认关闭，仅在显式启用时经 HandlerMount 挂载。维护模式
// 不挂载。所有操作/字段/对象范围/审计/行版本仍由 managedapi.Service 判定。

import (
	"fmt"
	"net/http"

	"github.com/kagurazakayashi/EvernightLogin/internal/managedapi/httpapi"
)

// BuildManagedAPIHTTPHandler 构造业务托管管理 API handler 与规范化前缀。
//
// 依赖真实服务：ManagedAPI（managedapi.Service）、Sessions（会话校验）与 SQLite
// 幂等存储（迁移 0045）。任一缺失时启动失败，不降级为匿名/无幂等模式。
func BuildManagedAPIHTTPHandler(deps Deps, services *Services, managed *ManagedServices,
	basePath string) (http.Handler, string, error) {
	if services == nil || services.Sessions == nil {
		return nil, "", fmt.Errorf("托管 API 缺少真实会话服务")
	}
	if managed == nil || managed.ManagedAPI == nil {
		return nil, "", fmt.Errorf("托管 API 缺少已装配的 managedapi 策略/操作服务")
	}
	idempotency, err := httpapi.NewSQLIdempotencyStore(deps.Store)
	if err != nil {
		return nil, "", fmt.Errorf("构造托管 API 幂等存储失败: %w", err)
	}
	handler, err := httpapi.New(httpapi.Options{
		Service: managed.ManagedAPI, Sessions: services.Sessions,
		Idempotency: idempotency, BasePath: basePath,
		MaxBodyBytes: httpapi.DefaultMaxBodyBytes,
		Now:          deps.Now, Logger: deps.Logger,
	})
	if err != nil {
		return nil, "", fmt.Errorf("构造托管 API HTTP handler 失败: %w", err)
	}
	return handler, handler.BasePath(), nil
}
