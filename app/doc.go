// Package app 提供 EvernightLogin 的公开嵌入式装配入口（步骤 138 / A01，
// 步骤 180 起与独立服务共用同一套基础装配与显式生命周期，步骤 181 起接通真实
// 认证/安全验证流程）。
//
// 它把 internal/serverapp 的真实装配暴露为只使用公开类型的门面：宿主可以在自己
// 的进程内打开临时 SQLite、执行首次 root 初始化、创建用户、密码登录、TOTP/Passkey
// 第二因素、撤销会话、受限恢复、敏感操作再次认证、显式启动后台任务并关闭，而不必
// 导入任何 internal 包。
//
// 生命周期与安全边界：
//   - Open 只打开配置/数据库/主密钥环/审计并构造真实领域服务、后台任务运行时与
//     login.Instance（State=StateNew），不监听端口、不启动后台任务/调度器、
//     不注册信号；后台任务只能由宿主显式调用 Runtime.Start 启动。
//   - Runtime 只关闭自己打开的数据库/实例/任务运行时；宿主注入的 Logger、
//     Database、Notifier 不被关闭；Close 幂等。
//   - 装配失败按相反顺序回滚已打开资源；Migrate=false 时未迁移库 fail-closed；
//     CreateMasterKey=false 时缺失主密钥 fail-closed；不会自动生成隐式默认密钥。
//   - 不提供跳过认证/伪造 root/关闭鉴权的入口；业务拒绝统一返回 *login.AppError
//     （已授权查询的“目标不存在”是正常结果，见下条）。
//     管理查询的“已授权但目标不存在”返回公开 *NotFoundError
//     （Code() == NotFoundCode，即 "NOT_FOUND"，HTTP 建议 404），用 IsNotFound 判断，
//     与 REQ_INVALID 参数错误、ACCESS_DENIED 权限拒绝区分。
//   - 请求关联：门面调用先统一解析请求编号（空编号生成、非法编号拒绝），同一编号
//     用于领域调用者/请求、领域审计与返回错误，便于按编号排查整条调用链。
//   - 会话授权与限流边界（步骤 208 / 251）：Sessions.Validate 只证明会话有效，业务/
//     管理授权必须再用 Sessions.Authorize 同时检查应用绑定与所需权限（复用授权内核）；
//     Authorize 不带 ResourceID 时只判定功能权限，需要具体资源结论时提供 ResourceID
//     由内核按数据范围判定，不能把功能权限当成资源归属已通过。ValidateCSRF 通过不会
//     提升受限会话权限。找回密码入口 Request/ValidateToken/
//     Complete 各有有界来源限流，键是宿主从可信边界解析的单一 IP（空来源共享桶，
//     伪造转发头链直接拒绝），日志不写 token、密码或找回链接。
//   - 认证/安全域（TOTP/Passkey/MFA/恢复代码/找回/客服）与敏感操作闸门由
//     internal/serverapp 与独立服务共用同一装配（步骤 181）；关闭 Passkey 不影响
//     TOTP 等可用能力，恢复代码只替代第二步并进入受限恢复会话。
//   - 受信管理门面（步骤 182）：Runtime.Admin() 提供管理员建用户（与自主注册开关
//     无关）、资料读写、应用/角色/权限登记、应用角色分配与权限查询；调用者必须由
//     Runtime.LocalAdmin()（本机受信操作者，自举通道）或 Runtime.AdminSession()
//     （真实管理用户会话，按当前权限/委派/再次认证判定）建立。
//   - HTTP 与页面挂载（步骤 183）：Options.HTTP 装配与独立服务共用的协议域/内置
//     页面/管理 API/HTTP 防护链；宿主用 Runtime.Handler()/Mount() 挂到自己的
//     http.Server，监听与生命周期归宿主。缺依赖或非法配置在 Open 阶段失败。
package app
