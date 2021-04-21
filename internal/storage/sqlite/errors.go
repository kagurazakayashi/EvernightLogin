package sqlite

import (
	"context"
	"database/sql"
	"errors"

	modernsqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// mapError 把驱动/上下文错误映射为安全的 storage.Error。上下文取消与超时保持
// 原样，便于调用方用 errors.Is 识别；已经是 storage.Error 的不重复包装。
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var storageError *storage.Error
	if errors.As(err, &storageError) {
		return err
	}
	var driverError *modernsqlite.Error
	if errors.As(err, &driverError) {
		kind, message := classifyErrorCode(driverError.Code())
		return storage.New(kind, message, err)
	}
	if errors.Is(err, sql.ErrConnDone) {
		return storage.New(storage.ErrClosed, "存储已关闭", err)
	}
	return storage.New(storage.ErrUnavailable, "数据库操作失败", err)
}

// classifyErrorCode 把 SQLite 结果码（可能带扩展码）映射为存储错误类别与安全
// 消息。公开消息不包含 SQL、表名、参数或文件路径。
func classifyErrorCode(code int) (error, string) {
	primary := code & 0xff
	switch primary {
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
		return storage.ErrBusy, "数据库正忙，请稍后重试"
	case sqlite3.SQLITE_CONSTRAINT:
		switch code {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE,
			sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
			sqlite3.SQLITE_CONSTRAINT_ROWID:
			return storage.ErrUniqueViolation, "数据已存在或唯一性约束冲突"
		default:
			return storage.ErrConstraint, "数据约束不满足"
		}
	case sqlite3.SQLITE_FULL:
		return storage.ErrDiskFull, "数据库磁盘空间不足"
	case sqlite3.SQLITE_READONLY, sqlite3.SQLITE_PERM:
		return storage.ErrPermission, "数据库文件为只读或权限不足"
	case sqlite3.SQLITE_CANTOPEN:
		return storage.ErrUnavailable, "无法打开数据库文件"
	case sqlite3.SQLITE_IOERR:
		return storage.ErrUnavailable, "数据库文件读写失败"
	case sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB:
		return storage.ErrCorrupt, "数据库文件损坏或格式不正确"
	default:
		return storage.ErrUnavailable, "数据库操作失败"
	}
}
