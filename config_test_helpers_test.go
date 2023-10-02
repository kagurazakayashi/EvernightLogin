package login

// 步骤 212 配置迁出后的根包测试辅助：server_tls_test/server_mtls_test 仍以根包
// 公开 API（别名桥）加载 YAML 配置；helper 只做测试断言包装，不包含产品逻辑。
// 正式实现与同口径 helper 位于 config 包的配置测试内。

import "testing"

// yamlBytes 把测试 YAML 文本转为字节。
func yamlBytes(text string) []byte {
	return []byte(text)
}

// mustLoad 加载配置并要求成功。
func mustLoad(t *testing.T, opts LoadOptions) Config {
	t.Helper()
	config, err := Load(opts)
	if err != nil {
		t.Fatalf("Load() 返回错误：%v", err)
	}
	return config
}
