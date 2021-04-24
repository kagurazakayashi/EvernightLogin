// Package audit 实现安全审计事件模型、脱敏差异、可信身份约束与可靠写入。
//
// 本包只负责安全审计，不负责 HTTP 访问日志、运行日志或审计查询/导出后台：
// 普通访问日志与运行日志仍由 internal/logging 处理，必须与安全审计分开。
//
// 事件由可信调用边界构造并传入（例如已验证会话、宿主显式身份、本地 CLI 或系统
// 任务）；本包不接受来自请求参数的自称身份。操作者类型明确区分：
//
//   - ActorUser：已认证的普通用户/操作者，actor_id 为稳定用户 ID；
//   - ActorSystem：系统任务/后台组件，actor_id 为稳定任务或组件标识；
//   - ActorLocalAdmin：本地管理员/CLI 应急操作者，actor_id 为本地操作者标识；
//   - ActorAnonymous：匿名失败尝试，无身份（actor_id 必须为空），不得填写虚假 root。
//
// 可靠写入：
//
//   - Record 在独立事务中追加事件；dedupe_key 相同的事件返回 ErrDuplicateEvent。
//   - RecordFailure 使用不受调用方取消影响的独立事务，确保业务事务回滚后失败
//     审计仍然保存；失败时返回 ErrAuditUnavailable 并触告警。
//   - ExecuteCritical 在同一个数据库事务中执行关键变更并写入成功事件：审计写入
//     失败会回滚业务变更并返回 ErrAuditUnavailable（对外映射为
//     AUDIT_WRITE_FAILED），同时触发运行告警；业务变更失败回滚后，失败事件由
//     独立事务补写，保证“失败可追踪”。
//
// 事件只允许接口定义字段入库：身份/动作/目标/结果/原因码/request_id/task_id
// 与脱敏后的有限变更差异；不存秘密、令牌、未受限大正文。SQLite 生产实现见
// internal/audit/sqlite，表结构见 migrations/0003_audit_events.sql。
package audit
