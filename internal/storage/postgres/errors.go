package postgres

import (
	"context"
	"database/sql/driver"
	"errors"

	"github.com/lib/pq"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// PostgreSQL SQLSTATE 到存储错误类别的映射（逐码为静态审查结论，尚未对真实
// PostgreSQL 逐码实测）。错误文本始终使用安全的固定描述，原始驱动错误只作为
// cause 保留给受限诊断，不包含密码、DSN 或 SQL 参数。
var sqlStateKinds = map[string]struct {
	kind    error
	message string
}{
	// 唯一性冲突。
	"23505": {storage.ErrUniqueViolation, "唯一性约束冲突"},
	// 并发写冲突/锁等待：可安全重试（REPEATABLE READ 序列化失败、死锁、锁不可用）。
	"40001": {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	"40P01": {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	"55P03": {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	// 数据约束不满足：NOT NULL/FK/CHECK/排他/长度/数值/非法 JSON（22P02）。
	"23502": {storage.ErrConstraint, "数据约束不满足"},
	"23503": {storage.ErrConstraint, "数据约束不满足"},
	"23514": {storage.ErrConstraint, "数据约束不满足"},
	"23P01": {storage.ErrConstraint, "数据约束不满足"},
	"22001": {storage.ErrConstraint, "数据约束不满足"},
	"22003": {storage.ErrConstraint, "数据约束不满足"},
	"22007": {storage.ErrConstraint, "数据约束不满足"},
	"22P02": {storage.ErrConstraint, "数据约束不满足"},
	"P0001": {storage.ErrConstraint, "数据约束不满足"},
	// 权限/认证。
	"42501": {storage.ErrPermission, "数据库权限不足"},
	"28000": {storage.ErrPermission, "数据库权限不足"},
	"28P01": {storage.ErrPermission, "数据库权限不足"},
	// 不可用：连接失败、库/表缺失、连接数满、服务器关闭。
	"08000": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08001": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08003": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08004": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08006": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08007": {storage.ErrUnavailable, "数据库暂时不可用"},
	"08P01": {storage.ErrUnavailable, "数据库暂时不可用"},
	"3D000": {storage.ErrUnavailable, "数据库暂时不可用"},
	"42P01": {storage.ErrUnavailable, "数据库暂时不可用"},
	"53300": {storage.ErrUnavailable, "数据库暂时不可用"},
	"57P01": {storage.ErrUnavailable, "数据库暂时不可用"},
	"57P02": {storage.ErrUnavailable, "数据库暂时不可用"},
	"57P03": {storage.ErrUnavailable, "数据库暂时不可用"},
	// 磁盘/资源耗尽。
	"53100": {storage.ErrDiskFull, "数据库磁盘空间不足"},
	"53200": {storage.ErrDiskFull, "数据库磁盘空间不足"},
}

// mapError 将 lib/pq 错误映射为 storage 可识别类别；未归类错误一律归为
// ErrUnavailable，不把原始文本暴露给调用方。
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
		return storage.New(storage.ErrUnavailable, "PostgreSQL 连接不可用", err)
	}
	var pqError *pq.Error
	if errors.As(err, &pqError) {
		if mapped, ok := sqlStateKinds[string(pqError.Code)]; ok {
			return storage.New(mapped.kind, mapped.message, err)
		}
		// 按 SQLSTATE 类别回退，覆盖同类别中未逐码登记的成员。
		if len(string(pqError.Code)) >= 2 {
			switch string(pqError.Code)[:2] {
			case "08":
				return storage.New(storage.ErrUnavailable, "数据库暂时不可用", err)
			case "23":
				return storage.New(storage.ErrConstraint, "数据约束不满足", err)
			case "28":
				// 认证类（28xxx）一律权限；注意 42 类含语法/对象不存在等非权限错误，
				// 只有明确登记 42501 才算权限，其余走通用不可用/操作失败。
				return storage.New(storage.ErrPermission, "数据库权限不足", err)
			}
		}
		return storage.New(storage.ErrUnavailable, "PostgreSQL 操作失败", err)
	}
	return storage.New(storage.ErrUnavailable, "PostgreSQL 操作失败", err)
}

// MapError 是 mapError 的导出形式，供宿主在外层包装驱动错误时复用。
func MapError(err error) error { return mapError(err) }
