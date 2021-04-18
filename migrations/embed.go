// Package migrations 内嵌已提交的数据库迁移文件。
//
// 迁移文件一旦被部署执行就不能修改，只能在末尾追加新版本；执行器的校验和会
// 拒绝已应用迁移的内容变化。SQLite 是当前唯一验证目标，其他数据库方言的迁移
// 在后续步骤单独维护，不能用 SQLite SQL 冒充其他数据库结构。
package migrations

import "embed"

// SQLite 是 SQLite 方言的已提交迁移文件集合。文件名必须符合
// NNNN_description.sql（四位数字版本号），由 internal/storage/migrate 校验。
//
//go:embed *.sql
var SQLite embed.FS
