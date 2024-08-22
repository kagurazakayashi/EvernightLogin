// Package dependencycheck 提供步骤 215 的轻量静态依赖检查（仅测试）。
//
// 不依赖 go 命令、网络、编译缓存；只使用 go/parser 扫描源码，便于离线复跑。
// 检查目标：
//   - 公共叶子不得 import internal/ 根包或 app 装配包；
//   - internal 非测试源码不得 import 根包；
//   - 根包 import 的 internal 实现不得经传递依赖回到根包；
//   - 根目录非测试文件只允许明确角色（别名桥/薄门面/Instance 实现）；
//   - 根/app 公开签名不暴露 internal 类型；
//   - 模块内 import 图无环；
//   - examples 外部 module 不直接 import Login internal；子模块不 import 父模块 root/internal。
//
// 这不是安全授权的替代：真实身份/授权/生命周期行为由各包测试与审计验证。
package dependencycheck
