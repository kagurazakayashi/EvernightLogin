package audit

import (
	"context"
	"database/sql"
)

// Tx 是审计包与关键变更共享的数据库事务视图。
//
// AppendEvent 在当前事务中写入审计事件；ExecContext 供关键变更执行自己的
// 参数化 SQL（本包不提供 ORM 或通用 CRUD）。任何返回错误都会使整个事务回滚，
// 调用方不能忽略错误继续提交。
type Tx interface {
	AppendEvent(ctx context.Context, event Event) error
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Store 是安全审计持久化契约，由 internal/audit/sqlite 提供生产 SQLite 实现。
//
// 实现约定：
//   - Append 在独立事务中写入事件；dedupe_key 已存在时返回 ErrDuplicateEvent，
//     其它失败返回 ErrAuditUnavailable（不得把失败当作成功）。
//   - RunCritical 开启数据库事务：带 dedupe_key 时先检查是否已存在（存在返回
//     ErrDuplicateEvent，不执行 change）；否则执行 change，成功后在同一事务中
//     写入 success 事件并提交。change 失败或事件写入失败时整体回滚；事件写入
//     失败必须返回可被 errors.Is(err, ErrAuditUnavailable) 识别的错误，供
//     Recorder 拒绝关键变更并告警。
//   - 所有方法传播 context；审计存储错误不得包含秘密、差异值或业务正文。
type Store interface {
	Append(ctx context.Context, event Event) error
	RunCritical(ctx context.Context, success Event, change func(ctx context.Context, tx Tx) error) error
}
