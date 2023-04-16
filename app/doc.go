// Package app 提供 EvernightLogin 的公开嵌入式装配入口（步骤 138 / A01）。
//
// 它把 internal/serverapp 已交付的真实服务装配暴露为只使用公开类型的门面：
// 宿主可以在自己的进程内打开临时 SQLite、执行首次 root 初始化、创建用户、
// 登录、权限检查、撤销会话与关闭，而不必导入任何 internal 包。
//
// 生命周期与安全边界：
//   - Open 只打开配置/数据库/密钥环并构造服务与 login.Instance（State=StateNew），
//     不监听端口、不启动后台任务/调度器、不注册信号；宿主仍拥有自己的 HTTP 服务。
//   - Runtime 只关闭自己打开的数据库/实例/任务运行时；宿主注入的 Logger 与
//     HTTP 资源不被关闭；Close 幂等。
//   - Migrate=false 时未迁移库 fail-closed；CreateMasterKey=false 时缺失主密钥
//     fail-closed；不会自动生成隐式默认密钥。
//   - 不提供跳过认证/伪造 root/关闭鉴权的入口；业务拒绝统一返回 *login.AppError。
package app
