package mysql

import (
	"context"
	"database/sql/driver"
	"errors"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// MySQL 错误码到存储错误类别的映射。错误文本始终使用安全的固定描述，原始驱动
// 错误只作为 cause 保留给受限诊断，不包含密码、DSN 或 SQL 参数。
const (
	errDuplicateEntry   = 1062 // ER_DUP_ENTRY
	errLockDeadlock     = 1213 // ER_LOCK_DEADLOCK
	errLockWaitTimeout  = 1205 // ER_LOCK_WAIT_TIMEOUT
	errNoSuchTable      = 1146 // ER_NO_SUCH_TABLE
	errBadDatabase      = 1049 // ER_BAD_DB_ERROR
	errAccessDenied     = 1044 // ER_DBACCESS_DENIED_ERROR
	errAccessDeniedUser = 1045 // ER_ACCESS_DENIED_ERROR
	errTooManyConns     = 1040 // ER_CON_COUNT_ERROR
	errReadOnly         = 1290 // ER_OPTION_PREVENTS_STATEMENT
	errCannotAddChild   = 1452 // ER_NO_REFERENCED_ROW_2
	errRowIsReferenced  = 1451 // ER_ROW_IS_REFERENCED_2
	errNoDefaultValue   = 1364 // ER_NO_DEFAULT_FOR_FIELD
	errTruncatedValue   = 1265 // WARN_DATA_TRUNCATED
	errDataTooLong      = 1406 // ER_DATA_TOO_LONG
	errSignal           = 1644 // ER_SIGNAL_EXCEPTION（触发器 SIGNAL SQLSTATE '45000'）
	errCheckConstraint  = 3819 // ER_CHECK_CONSTRAINT_VIOLATED
)

// mapError 将 go-sql-driver/mysql 错误映射为 storage 可识别类别；未归类错误一律
// 归为 ErrUnavailable，不把原始文本暴露给调用方。
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var storageError *storage.Error
	if errors.As(err, &storageError) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, driver.ErrBadConn) {
		return storage.New(storage.ErrUnavailable, "MySQL 连接不可用", err)
	}
	var mysqlError *gomysql.MySQLError
	if errors.As(err, &mysqlError) {
		switch mysqlError.Number {
		case errDuplicateEntry:
			return storage.New(storage.ErrUniqueViolation, "唯一性约束冲突", err)
		case errLockDeadlock, errLockWaitTimeout:
			return storage.New(storage.ErrBusy, "数据库正忙或存在并发写冲突", err)
		case errCannotAddChild, errRowIsReferenced, errNoDefaultValue,
			errTruncatedValue, errDataTooLong, errCheckConstraint, errSignal:
			return storage.New(storage.ErrConstraint, "数据约束不满足", err)
		case errAccessDenied, errAccessDeniedUser:
			return storage.New(storage.ErrPermission, "数据库权限不足", err)
		case errTooManyConns, errNoSuchTable, errBadDatabase, errReadOnly:
			return storage.New(storage.ErrUnavailable, "数据库暂时不可用", err)
		default:
			return storage.New(storage.ErrUnavailable, "MySQL 操作失败", err)
		}
	}
	return storage.New(storage.ErrUnavailable, "MySQL 操作失败", err)
}

// MapError 是 mapError 的导出形式，供宿主在外层包装驱动错误时复用。
func MapError(err error) error { return mapError(err) }

// 说明：映射表是静态审查结论，尚未对真实 MySQL 服务器逐码实测。
