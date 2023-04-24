package protocolapi

import "net/http"

// registerRoutes 把端点注册进本包的精确路径路由表。只有依赖真实具备的端点才会
// 注册：设备码需要 EnableDeviceFlow，状态查询需要 EnableIntrospection，扫码登录
// 需要注入 QRLogin 服务。未挂载的端点返回 404，不会以“空实现成功”出现。
func (s *Server) registerRoutes() {
	s.routes[s.routePath(PathDiscovery)] = http.HandlerFunc(s.handleDiscovery)
	s.routes[s.routePath(PathJWKS)] = http.HandlerFunc(s.handleJWKS)
	s.routes[s.routePath(PathAuthorize)] = http.HandlerFunc(s.handleAuthorize)
	s.routes[s.routePath(PathToken)] = http.HandlerFunc(s.handleToken)
	s.routes[s.routePath(PathUserInfo)] = http.HandlerFunc(s.handleUserInfo)
	s.routes[s.routePath(PathRevoke)] = http.HandlerFunc(s.handleRevoke)
	if s.enabledInspect {
		s.routes[s.routePath(PathIntrospect)] = http.HandlerFunc(s.handleIntrospect)
	}
	if s.opts.TokenAuthorize != nil {
		s.routes[s.routePath(PathTokenAuthorize)] = s.opts.TokenAuthorize
	}
	if s.enabledDevice {
		s.routes[s.routePath(PathDeviceAuthorization)] = http.HandlerFunc(s.handleDeviceAuthorization)
		s.routes[s.routePath(PathDeviceCancel)] = http.HandlerFunc(s.handleDeviceCancel)
	}
	if s.opts.QRLogin != nil {
		s.routes[s.routePath(PathQRRequest)] = http.HandlerFunc(s.handleQRRequest)
		s.routes[s.routePath(PathQRStatus)] = http.HandlerFunc(s.handleQRStatus)
		s.routes[s.routePath(PathQRClaim)] = http.HandlerFunc(s.handleQRClaim)
		s.routes[s.routePath(PathQRCancel)] = http.HandlerFunc(s.handleQRCancel)
		s.routes[s.routePath(PathQRRegenerate)] = http.HandlerFunc(s.handleQRRegenerate)
		s.routes[s.routePath(PathQRPrompt)] = http.HandlerFunc(s.handleQRPrompt)
		s.routes[s.routePath(PathQRDecision)] = http.HandlerFunc(s.handleQRDecision)
	}
}
