package sqlserver

import (
	"context"
	"database/sql/driver"
	"errors"
	"net"

	mssql "github.com/microsoft/go-mssqldb"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

// SQL Server 错误号到存储错误类别的映射（逐号为静态审查结论，尚未对真实 SQL
// Server 逐号实测）。错误文本始终使用安全的固定描述，原始驱动错误只作为 cause
// 保留给受限诊断，不包含密码、DSN、SQL 或参数。
//
// 错误号来自 SQL Server 文档与驱动配置：
//   - 2627/2601 唯一约束/唯一索引冲突；2601 是唯一索引重复键。
//   - 1205 死锁牺牲者、1222 锁请求超时：可安全重试。
//   - 547 外键/CHECK 约束冲突、515 NOT NULL、8152/2628 截断、8114/245 转换失败。
//   - 229/230 权限不足、18456 登录失败。
//   - 4060 数据库无法打开、40613/40501 云数据库暂不可用、10053/10054 连接中断。
//   - 9002 事务日志满、1105 磁盘空间不足。
var sqlErrorKinds = map[int32]struct {
	kind    error
	message string
}{
	// 唯一性冲突。
	2627: {storage.ErrUniqueViolation, "唯一性约束冲突"},
	2601: {storage.ErrUniqueViolation, "唯一性约束冲突"},
	// 并发写冲突/锁：可安全重试。
	1205: {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	1222: {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	3960: {storage.ErrBusy, "数据库正忙或存在并发写冲突"},
	// 数据约束不满足。
	547:  {storage.ErrConstraint, "数据约束不满足"},
	515:  {storage.ErrConstraint, "数据约束不满足"},
	8152: {storage.ErrConstraint, "数据约束不满足"},
	2628: {storage.ErrConstraint, "数据约束不满足"},
	8114: {storage.ErrConstraint, "数据约束不满足"},
	245:  {storage.ErrConstraint, "数据约束不满足"},
	257:  {storage.ErrConstraint, "数据约束不满足"},
	// 权限/认证。
	229:   {storage.ErrPermission, "数据库权限不足"},
	230:   {storage.ErrPermission, "数据库权限不足"},
	18456: {storage.ErrPermission, "数据库权限不足"},
	// 不可用：连接失败、库/表缺失、连接数满、服务器关闭、云数据库暂不可用。
	4060:  {storage.ErrUnavailable, "数据库暂时不可用"},
	40613: {storage.ErrUnavailable, "数据库暂时不可用"},
	40501: {storage.ErrUnavailable, "数据库暂时不可用"},
	40540: {storage.ErrUnavailable, "数据库暂时不可用"},
	10053: {storage.ErrUnavailable, "数据库暂时不可用"},
	10054: {storage.ErrUnavailable, "数据库暂时不可用"},
	10060: {storage.ErrUnavailable, "数据库暂时不可用"},
	208:   {storage.ErrUnavailable, "数据库暂时不可用"},
	207:   {storage.ErrUnavailable, "数据库暂时不可用"},
	2812:  {storage.ErrUnavailable, "数据库暂时不可用"},
	102:   {storage.ErrUnavailable, "数据库暂时不可用"},
	1801:  {storage.ErrUnavailable, "数据库暂时不可用"},
	3949:  {storage.ErrUnavailable, "数据库暂时不可用"},
	// 磁盘/资源耗尽。
	9002: {storage.ErrDiskFull, "数据库磁盘空间不足"},
	1105: {storage.ErrDiskFull, "数据库磁盘空间不足"},
}

// mapError 将 SQL Server 驱动错误映射为 storage 可识别类别；未归类错误一律归为
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
		return storage.New(storage.ErrUnavailable, "SQL Server 连接不可用", err)
	}
	var mssqlError mssql.Error
	if errors.As(err, &mssqlError) {
		if mapped, ok := sqlErrorKinds[mssqlError.Number]; ok {
			return storage.New(mapped.kind, mapped.message, err)
		}
		// 按错误号高位类别回退，覆盖同类别中未逐号登记的成员。5xx 是服务器端错误，
		// 不做猜测；只有明确登记的号才分类，其余走通用不可用。
		return storage.New(storage.ErrUnavailable, "SQL Server 操作失败", err)
	}
	var netError net.Error
	if errors.As(err, &netError) {
		return storage.New(storage.ErrUnavailable, "数据库暂时不可用", err)
	}
	return storage.New(storage.ErrUnavailable, "SQL Server 操作失败", err)
}

// MapError 是 mapError 的导出形式，供宿主在外层包装驱动错误时复用。
func MapError(err error) error { return mapError(err) }
