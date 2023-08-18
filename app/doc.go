// Package app 提供 EvernightLogin 的公开嵌入式装配入口（步骤 138 / A01，
// 步骤 180 起与独立服务共用同一套基础装配与显式生命周期）。
//
// 它把 internal/serverapp 的真实装配暴露为只使用公开类型的门面：宿主可以在自己
// 的进程内打开临时 SQLite、执行首次 root 初始化、创建用户、登录、权限检查、撤销
// 会话、显式启动后台任务并关闭，而不必导入任何 internal 包。
//
// 生命周期与安全边界：
//   - Open 只打开配置/数据库/主密钥环/审计并构造真实领域服务、后台任务运行时与
//     login.Instance（State=StateNew），不监听端口、不启动后台任务/调度器、
//     不注册信号；后台任务只能由宿主显式调用 Runtime.Start 启动。
//   - Runtime 只关闭自己打开的数据库/实例/任务运行时；宿主注入的 Logger、
//     Database、Notifier 不被关闭；Close 幂等。
//   - 装配失败按相反顺序回滚已打开资源；Migrate=false 时未迁移库 fail-closed；
//     CreateMasterKey=false 时缺失主密钥 fail-closed；不会自动生成隐式默认密钥。
//   - 不提供跳过认证/伪造 root/关闭鉴权的入口；业务拒绝统一返回 *login.AppError。
//   - 安全域（MFA/Passkey/恢复）、管理门面与 HTTP/页面挂载由后续步骤（181-183）
//     在同一共享装配上继续补齐，本包不复制第二套业务逻辑。
package app
