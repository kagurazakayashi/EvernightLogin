// Package adminapi 提供宿主与 CLI 使用的在线管理 JSON API（步骤 84 阻塞 B3 的
// 在线管理缺口）。
//
// 本包只做传输与装配：认证复用 internal/session 的管理会话，授权、敏感操作
// （再次认证 / 强认证策略）、数据范围、幂等与终态语义全部由既有领域服务在每次
// 请求中重新判定；本包不复制业务规则、不缓存授权结论、不直接写数据库。它不是
// 第二套管理权限实现，也不把页面 HTML 处理器改写成 JSON。
//
// # 认证与 CSRF 契约
//
//   - 会话秘密来源与会话服务一致：Authorization: Bearer <会话秘密> 或会话 Cookie
//     （默认 __Host-login_session）。两种来源都调用
//     session.Service.AuthorizeManagement，每次请求重新校验会话状态、账户状态、
//     安全版本与强认证新鲜度（StrongAuthMaxAge），并拒绝受限会话。
//   - 强认证未完成或已过期一律 fail-closed（403 REAUTH_REQUIRED）；严重错误不
//     降级为“只读放行”。
//   - Cookie 会话的所有非安全方法必须携带与会话绑定的 X-CSRF-Token，并由
//     session.Service.ValidateCSRFToken 校验；缺失或无效返回 403 ACCESS_DENIED。
//     Bearer 会话秘密不随浏览器自动发送，不要求 CSRF 头。
//   - Origin/Referer 允许列表、限流、请求体全局上限、并发上限、请求期限与安全
//     响应头由宿主既有 HTTP 防护中间件（internal/transport）负责。本包额外提供
//     请求体上限与请求期限作为防御性兜底，但不替代宿主中间件。管理 API 不应
//     配置跨源 CORS；默认无 CORS 头，浏览器跨源请求被阻止。
//
// # 权限与敏感操作映射
//
// 每次请求的权限、作用范围与数据范围交集全部在领域服务内判定，本包只传入可信
// 调用者。端点与领域权限/敏感操作的对应关系：
//
//	GET  /meta                                  管理会话（基线）
//	GET  /error-codes                           管理会话（基线）
//	GET  /audit/events                           auditops.Query：audit.read + 数据范围
//	GET  /audit/events/{id}                      auditops.GetEvent：audit.read + 数据范围
//	GET  /audit/retention                        auditops.Retention：已认证会话
//	GET  /audit/exports                          auditops.ListExports：audit.export
//	GET  /audit/exports/{id}                     auditops.GetExport：audit.export
//	GET  /audit/exports/{id}/download            auditops.OpenExportFile：audit.export + 每次重授权
//	POST /audit/exports                          auditops.StartExport：audit.export + audit.export 敏感策略
//	POST /audit/exports/{id}/cancel              auditops.CancelExport：root/记录授权 + 取消审计
//	GET  /audit/purge-runs                       auditops.ListPurgeRuns：root
//	GET  /audit/purge-runs/{id}                  auditops.GetPurgeRun：root
//	POST /audit/purge/preview                    auditops.PreviewPurge：root（只读）
//	POST /audit/purge                            auditops.StartPurge：root + audit.purge 敏感策略 + 确认 + 原因
//	POST /audit/purge/{id}/cancel                auditops.CancelPurge：root
//	PUT  /audit/retention                        auditops.SetRetention：root + audit.retention.update 敏感策略 + 版本并发
//	GET  /reports                                reports.HistoryList：reports.read + 数据范围
//	GET  /reports/{id}                           reports.Get：reports.read + 资源归属
//	GET  /reports/{id}/snapshot                  reports.GetSnapshot：reports.read + 资源归属
//	POST /reports/{id}/download-tickets          reports.IssueDownloadTicket：reports.export + 敏感策略
//	POST /reports/download-tickets/redeem        reports.RedeemDownloadTicket：单次消费 + 当前权限
//	POST /reports/{id}/cancel                    reports.Cancel：reports.read/所有权 + 状态机
//	POST /reports/{id}/retry                     reports.Retry：reports.generate + 敏感策略
//	GET  /reports/cleanup-preview                reports.CleanupPreview：reports.cleanup
//	POST /reports/cleanup                        reports.CleanupExecute：reports.cleanup + 敏感策略 + 确认 + 原因
//	GET  /report-plans                           reports.PlanService.List：reports.schedule.manage
//	GET  /report-plans/{id}                      reports.PlanService.Get：reports.schedule.manage
//	POST /report-plans                           reports.PlanService.Create：read/schedule.manage/generate/export + reauth + 确认 + 审计
//	PUT  /report-plans/{id}                      reports.PlanService.Update：同上 + 行版本乐观并发
//	POST /report-plans/{id}/enabled              reports.PlanService.SetEnabled：同上 + 原因
//	GET  /report-plans/{id}/delete-preview       reports.PlanService.DeletePreview：reports.schedule.manage
//	DELETE /report-plans/{id}                    reports.PlanService.Delete：同上 + reauth + 确认 + 原因
//	GET  /backups                                backupadmin.ListArtifacts：backups.read
//	GET  /backups/{id}                           backupadmin.GetArtifact：backups.read
//	GET  /backups/capabilities                   backupadmin.Capabilities：backups.read
//	GET  /backups/jobs                           backupadmin.ListJobs：backups.read
//	GET  /backups/jobs/{id}                      backupadmin.GetJob：backups.read
//	GET  /backups/schedules                      backupadmin.ListSchedules：backups.read
//	GET  /backups/schedules/{id}                 backupadmin.GetSchedule：backups.read
//	POST /backups/schedules                      backupadmin.CreateSchedule：backups.create + reauth + 确认 + 审计
//	PUT  /backups/schedules/{id}                 backupadmin.UpdateSchedule：同上
//	POST /backups/schedules/{id}/enabled         backupadmin.SetScheduleEnabled：同上 + 原因
//	DELETE /backups/schedules/{id}               backupadmin.DeleteSchedule：backups.create + reauth + 确认 + 原因
//	POST /backups                                backupadmin.EnqueueBackup：backups.create + 敏感策略 + 确认
//	POST /backups/jobs/{id}/cancel               backupadmin.CancelJob：backups.cancel + 确认 + 原因
//	POST /backups/{id}/download-tickets          backupadmin.IssueDownloadTicket：backups.export + 敏感策略 + 确认
//	POST /backups/download-tickets/redeem        backupadmin.RedeemDownloadTicket：单次消费 + 当前权限
//	GET  /backups/retention                      backupadmin.Retention：backups.read
//	PUT  /backups/retention                      backupadmin.SaveRetention：backups.read/管理 + 敏感策略 + 确认 + 版本并发
//	GET  /backups/cleanup-preview                backupadmin.CleanupPreview：backups.read
//	POST /backups/cleanup                        backupadmin.EnqueueCleanup：backups.create + 敏感策略 + 确认
//	GET  /tasks/{id}                             task.Executor.Get/Attempts + TaskAuthorizer：`diagnostics.read` + 数据范围/属主（拒绝 403、不存在 404）；显式剔除任务载荷
//	GET  /diagnostics                           宿主 Diagnostics：diagnostics.read + 明确 system/应用范围；只读脱敏运行状态/队列/配置待重启/关联错误白名单
//	GET  /diagnostics/errors                    同上 + request_id 白名单关联错误（有界条数，不返回审计 detail）
//	GET  /diagnostics/export                    同上 + 有界脱敏导出（JSON 快照 + 可选关联错误）
//	GET  /notifications                          宿主 NotificationService：脱敏配置/启用状态；未装配 503 MAIL_DIAGNOSTICS_UNAVAILABLE
//	POST /notifications/test                     本地捕获 notifier：执行前核验 LocalCapture/DeliveryMode=local_capture；reauth + 真实审计 + 确认；禁止真实外发；未装配或非本地捕获 503 NOTIFICATION_TEST_DISABLED
//	GET  /sessions                               session.AdminListSessions：强认证管理会话 + sessions.revoke 范围授权 + root/受保护目标拒绝 + 真实读取审计（只返回公开摘要，不含秘密）
//	POST /sessions/revoke                        session.AdminRevoke：session.revoke.other 敏感策略 + sessions.revoke 范围授权 + 确认/理由 + 原子撤销 + 真实操作者审计
//
// 凭据、路径与内部错误不进入响应：响应只包含领域服务公开视图的白名单字段，
// 下载端点由本包打开受控文件并流式输出字节，绝不回显宿主路径。
//
// # 统一响应
//
// 成功：
//
//	{"ok":true,"request_id":"req_...","data":{...}}
//
// 失败（错误码必须来自根包注册表投影，HTTP 状态与默认消息同源）：
//
//	{"ok":false,"code":"ACCESS_DENIED","message":"请求未获准","request_id":"req_..."}
//
// 请求编号优先复用上游传入的值（宿主传输层），否则内部加密随机生成，并在
// X-Request-ID 响应头回显；请求编号只用于关联与排障，不参与授权。
//
// # 写操作语义
//
// 所有写操作要求 confirm=true（确认不是授权），取消/清理/保留策略还要求原因，
// 原因进入真实审计。异步任务“已提交/已接受取消”不等于“完成/已取消”：响应
// 返回领域服务的真实任务状态。一次性的报告/备份下载令牌只返回一次，兑换时再次
// 授权并重新检查产物状态，重复兑换或撤权后兑换由领域服务拒绝。
//
// 敏感操作（审计导出/清理/保留策略、报告下载令牌/清理/重试、备份创建/下载令牌/
// 保留策略/清理、管理员强制下线）由领域服务调用注入的 reauth.OperationRunner 与
// internal/policy 判定；未装配策略或未满足强认证要求时领域服务 fail-closed，本包
// 不做降级。CLI 的一次性再次认证证明（步骤 186，X-Login-Confirmation）由宿主
// 中间件在校验并原子消费后向请求 ctx 注入 reauth 信号，本包不解读该头。
// 通知测试等真实外发能力不在本包实现（禁止真实外发），见“未实现”。
//
// # 集成步骤
//
//  1. 宿主装配真实领域服务（auditops.New / reports.New / reports.NewPlanService /
//     backupadmin.New；审计写入用 internal/audit 的真实 Recorder），把各自的
//     Authorizer/Root/Sensitive/Enqueuer/Canceller 接到 internal/authz、
//     internal/policy 与 internal/reauth 的生产实现上，任务处理器注册到
//     internal/task Executor。本包的 contracts.go 在编译期要求它们满足接口。
//  2. 构造 Options：Session 传 *session.Service；ErrorCodes 传根包
//     login.RegisteredErrorCodes() 的投影；按实际装配传入服务指针。
//  3. server, err := adminapi.New(options)；handler := server.Handler()。
//  4. 把 handler 挂在内置页面/传输层之后（同一 HTTP 防护中间件、同一信任边界、
//     同一监听），例如 `server.Mount(mux)` 或作为内部 http.ServeMux 的子路由。
//     不要为管理 API 另起监听或跳过 CSRF/限流/代理信任校验。
//  5. 宿主确保管理会话强认证可用；MFA/管理强认证未实现时管理 API 会持续
//     fail-closed（403 REAUTH_REQUIRED），这是预期行为，不得用本地白名单绕过。
//  6. CLI 可通过 Authorization: Bearer <管理会话秘密> 调用（仍需强认证会话）；
//     本地应急命令继续走 cmd/loginctl 的独立本地边界，不混用本 API。
//
// # 未实现（partial，如实声明）
//
//   - 报告立即生成端点未开放（只有历史/快照读取与计划管理）；异步生成仍由
//     领域服务与宿主任务执行器负责。
//   - 通知测试执行前先读取 NotificationStatus 并要求 LocalCapture=true 且
//     DeliveryMode=="local_capture"；任何真实投递模式或状态读取失败都 fail-closed
//     （503 NOTIFICATION_TEST_DISABLED）并写拒绝审计，测试器零调用。
//   - 备份通知列表与“真实投递测试”未开放：根配置无 SMTP/mailer 装配，规则禁止
//     真实外发。POST /notifications/test 只在宿主注入本地捕获 notifier 时执行并
//     返回捕获摘要，绝不真实外发；未装配时返回稳定能力码，绝不伪成功。
//   - 任务列表（无 id）未开放：internal/task.Store 不提供列表契约，本包不伪造
//     列表；CLI 侧另行直读 jobs 索引，本包只开放任务详情与尝试历史。
//   - 通知测试的输出仅代表“本地捕获器收到消息”，不代表任何真实通道可达。
//   - 限流、并发上限、CORS、代理信任与 Origin/Referer 校验依赖宿主中间件，本包
//     不重复实现；任务提示中的“限流依赖宿主中间件”即指此边界。
package adminapi
