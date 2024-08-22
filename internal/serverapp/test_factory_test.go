package serverapp

import (
	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/lifecycle"
)

// 测试专用：为旧有 serverapp 集成测试注入根包实例工厂，避免每个 ServeOptions
// 字面量重复设置；生产 RunServe 仍要求 cmd 显式注入 NewInstance。
func init() {
	defaultInstanceFactory = func(options lifecycle.Options) (lifecycle.Runner, error) {
		instance, err := login.New(options)
		if err != nil {
			return nil, err
		}
		return instance, nil
	}
}
