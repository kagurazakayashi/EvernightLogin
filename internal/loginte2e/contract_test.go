package loginte2e

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/protocolapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
)

// TestPathContractMatchesProtocolAPI 守护工具硬编码的协议路径与服务端导出的路径
// 常量一致：工具 CLI 刻意不 import protocolapi（避免把服务端领域装配进测试工具
// 二进制），因此用测试做漂移检测。
func TestPathContractMatchesProtocolAPI(t *testing.T) {
	cases := map[string]string{
		pathDiscovery:           protocolapi.PathDiscovery,
		pathJWKS:                protocolapi.PathJWKS,
		pathAuthorize:           protocolapi.PathAuthorize,
		pathToken:               protocolapi.PathToken,
		pathUserInfo:            protocolapi.PathUserInfo,
		pathRevoke:              protocolapi.PathRevoke,
		pathIntrospect:          protocolapi.PathIntrospect,
		pathDeviceAuthorization: protocolapi.PathDeviceAuthorization,
		pathDeviceCancel:        protocolapi.PathDeviceCancel,
		pathQRRequest:           protocolapi.PathQRRequest,
		pathQRStatus:            protocolapi.PathQRStatus,
		pathQRClaim:             protocolapi.PathQRClaim,
		pathQRCancel:            protocolapi.PathQRCancel,
		pathQRPrompt:            protocolapi.PathQRPrompt,
		pathQRDecision:          protocolapi.PathQRDecision,
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("工具路径常量 %q 与服务端 %q 不一致", got, want)
		}
	}
}

// TestAdminContractMatchesAdminAPI 守护管理 API 默认前缀。
func TestAdminContractMatchesAdminAPI(t *testing.T) {
	if defaultAdminBasePath != adminapi.DefaultBasePath {
		t.Fatalf("工具管理前缀 %q 与 adminapi.DefaultBasePath %q 不一致",
			defaultAdminBasePath, adminapi.DefaultBasePath)
	}
	if DefaultSessionCookieName != session.DefaultCookieName {
		t.Fatalf("工具会话 Cookie 名 %q 与 session.DefaultCookieName %q 不一致",
			DefaultSessionCookieName, session.DefaultCookieName)
	}
}
