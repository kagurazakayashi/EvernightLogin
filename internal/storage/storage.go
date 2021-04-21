// Package storage 定义数据库存储共享契约与安全错误类型。
//
// 具体数据库实现在 internal/storage/sqlite；本包不依赖特定驱动，负责让调用方
// 使用 errors.Is 识别并发、唯一性、权限、磁盘与损坏等状态，并让公开错误文本
// 不含原始 SQL、数据库路径或驱动细节。
package storage

import (
	"database/sql"
	"errors"
)

// 可识别的存储错误类别。对客户端/公开日志只展示安全消息；原始驱动错误通过
// Error 的 cause 保留给受限诊断，不得直接返回或打印给普通调用者。
var (
	// ErrClosed 表示存储已关闭。
	ErrClosed = errors.New("存储已关闭")
	// ErrBusy 表示数据库正忙或存在并发写冲突，属于可重试状态。
	ErrBusy = errors.New("数据库正忙或存在并发写冲突")
	// ErrUniqueViolation 表示唯一性约束冲突。
	ErrUniqueViolation = errors.New("唯一性约束冲突")
	// ErrConstraint 表示其他数据约束不满足（外键、CHECK、NOT NULL 等）。
	ErrConstraint = errors.New("数据约束不满足")
	// ErrVersionConflict 表示乐观并发版本冲突，需要重新读取后再决定。
	ErrVersionConflict = errors.New("数据版本冲突")
	// ErrUnavailable 表示数据库暂时不可用或无法打开。
	ErrUnavailable = errors.New("数据库暂时不可用")
	// ErrPermission 表示数据库文件或目录权限不足。
	ErrPermission = errors.New("数据库文件或目录权限不足")
	// ErrDiskFull 表示数据库磁盘空间不足。
	ErrDiskFull = errors.New("数据库磁盘空间不足")
	// ErrCorrupt 表示数据库文件损坏或格式不正确。
	ErrCorrupt = errors.New("数据库文件损坏或格式不正确")
)

// Error 是带安全公开消息的存储错误。Error() 只返回固定类别消息，不包含驱动
// 原始错误、SQL、文件路径或参数；errors.Is 可识别类别，Unwrap 保留原因链供
// 受限诊断使用。
type Error struct {
	kind    error
	message string
	cause   error
}

// New 构造存储错误。kind 应为上面定义的哨兵之一；message 必须是不含 SQL、
// 路径、参数或秘密的公开文本；cause 可以是原始驱动错误，仅用于内部诊断。
func New(kind error, message string, cause error) *Error {
	if kind == nil {
		kind = ErrUnavailable
	}
	if message == "" {
		message = kind.Error()
	}
	return &Error{kind: kind, message: message, cause: cause}
}

// Error 返回安全公开文本。
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Kind 返回错误类别哨兵。
func (e *Error) Kind() error {
	if e == nil {
		return ErrUnavailable
	}
	return e.kind
}

// Cause 返回原始原因，仅限内部诊断；不得直接返回客户端或写入普通日志。
func (e *Error) Cause() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Unwrap 同时暴露类别与原因，使 errors.Is 能识别类别、errors.As 能追溯驱动错误。
func (e *Error) Unwrap() []error {
	if e == nil {
		return nil
	}
	unwrapped := make([]error, 0, 2)
	if e.kind != nil {
		unwrapped = append(unwrapped, e.kind)
	}
	if e.cause != nil {
		unwrapped = append(unwrapped, e.cause)
	}
	return unwrapped
}

// CheckVersionedUpdate 用于乐观并发更新：调用方执行
// `UPDATE ... SET row_version=row_version+1 ... WHERE id=? AND row_version=?`
// 后用本函数检查受影响行数。0 行表示版本已过期（ErrVersionConflict），多行表示
// 调用方条件写错，也拒绝。数据库无法确认行数时返回 ErrUnavailable。
func CheckVersionedUpdate(result sql.Result) error {
	if result == nil {
		return New(ErrUnavailable, "无法确认更新结果", nil)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return New(ErrUnavailable, "无法确认更新结果", err)
	}
	switch {
	case affected == 0:
		return New(ErrVersionConflict, "数据已被其他操作修改，请重新读取后再重试", nil)
	case affected != 1:
		return New(ErrVersionConflict, "版本更新影响了非预期的行数", nil)
	default:
		return nil
	}
}
