// Package ui 是 EvernightLogin 内置 Web 页面、模板与静态资源的公共实现。
//
// 边界（步骤 214）：
//   - 本包是公共叶子包，不依赖根包 login，也不依赖本模块 internal/；
//   - 页面契约与 WebUI 实现在此维护，根包仅通过 alias_ui.go 提供迁移期兼容别名；
//   - 模板/静态资源/中文文案通过本包 embed.go 内嵌，逻辑路径保持 web/...；
//   - 页面只调用宿主注入的 Backend 与真实领域服务，不在前端缓存权限或解析身份。
package ui
