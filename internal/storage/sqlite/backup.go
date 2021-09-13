package sqlite

import (
	"context"
	"os"
	"strings"

	modernsqlite "modernc.org/sqlite"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage"
)

const (
	// backupStepPages 是单次 sqlite3_backup_step 复制的页数。分批复制使备份过程
	// 可以在页之间检查 ctx 取消，并为进度回调提供稳定粒度（默认 4 KiB 页时约
	// 1 MiB 一批）。
	backupStepPages = 256
	// maxBackupRestarts 是允许的在线备份重启次数。SQLite 在源数据库被其它连接
	// 修改且备份无法继续使用同一读快照时会自动重启；持续重启说明写入压力过大，
	// 必须有界失败，不能无限重试。
	maxBackupRestarts = 5
)

// BackupProgress 是在线备份页进度回调。done/total 是 SQLite 报告的已完成页数与
// 当前页总数；源库在备份期间被修改导致重启时 total 可能变化，调用方应把进度
// 当作估计值而不是单调契约。
type BackupProgress func(donePages, totalPages int)

// onlineBackupConn 是 modernc.org/sqlite 连接上的在线备份扩展方法。驱动没有把
// 该方法暴露在 database/sql 标准接口上，只能通过 sql.Conn.Raw 断言后使用；升级
// 驱动时必须回归本文件。
type onlineBackupConn interface {
	NewBackup(dstURI string) (*modernsqlite.Backup, error)
}

// OnlineBackup 使用 SQLite 官方在线备份机制（sqlite3_backup API）把当前数据库的
// 一致性快照复制到 destination。它不复制运行中的主数据库文件，也不会读取 WAL /
// journal 旁文件：快照由 SQLite 在源连接上通过读事务生成，备份期间的并发写入不会
// 产生半新半旧的页面集合。
//
// destination 必须是尚不存在的文件路径（父目录必须已存在）；本方法不会覆盖已有
// 文件。成功返回时目标文件已由驱动关闭并落盘到 SQLite 认为的一致状态，调用方仍
// 应按需 fsync 并尽快删除明文快照。ctx 取消时立即停止后续页复制，目标文件可能
// 不完整，由调用方负责清理。
//
// 错误映射为 storage.Error（未分类驱动错误为 ErrUnavailable），不包含路径、SQL
// 或页内容。上下文取消/超时保持原样。
func (s *Store) OnlineBackup(ctx context.Context, destination string, progress BackupProgress) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if strings.TrimSpace(destination) == "" {
		return storage.New(storage.ErrUnavailable, "在线备份目标路径为空", nil)
	}
	// 驱动把一个 '?' 之后的内容当作 DSN 参数；`#` 也不属于受支持的文件名。
	// 目标路径由本模块生成，遇到这些字符说明调用方传入了错误路径，直接拒绝。
	if strings.ContainsAny(destination, "?#") {
		return storage.New(storage.ErrUnavailable, "在线备份目标路径包含非法字符", nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return storage.New(storage.ErrUnavailable, "在线备份目标文件已存在，拒绝覆盖", nil)
	} else if !os.IsNotExist(err) {
		return storage.New(storage.ErrPermission, "无法检查在线备份目标路径", nil)
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return mapError(err)
	}
	defer conn.Close()
	rawErr := conn.Raw(func(driverConn any) error {
		backupConn, ok := driverConn.(onlineBackupConn)
		if !ok {
			// 驱动升级后接口变化时明确失败，绝不退回到复制主文件。
			return storage.New(storage.ErrUnavailable, "当前 SQLite 驱动不支持在线备份接口", nil)
		}
		return copyDatabase(ctx, backupConn, destination, progress)
	})
	if rawErr != nil {
		return rawErr
	}
	return nil
}

// copyDatabase 在驱动原始连接上执行 SQLite 在线备份循环。它必须运行在
// sql.Conn.Raw 回调内，使源连接在整个复制期间不被连接池复用。
func copyDatabase(ctx context.Context, backupConn onlineBackupConn, destination string,
	progress BackupProgress) error {
	backup, err := backupConn.NewBackup(destination)
	if err != nil {
		return mapError(err)
	}
	finished := false
	defer func() {
		// 失败或提前返回时释放备份句柄并关闭驱动创建的目标连接；正常路径已在
		// 下面调用 Finish，避免重复释放。
		if !finished {
			_ = backup.Finish()
		}
	}()
	lastTotal := 0
	restarts := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, stepErr := backup.Step(backupStepPages)
		if stepErr != nil {
			return mapError(stepErr)
		}
		total := backup.PageCount()
		remaining := backup.Remaining()
		done := total - remaining
		if done < 0 {
			done = 0
		}
		if total < 0 {
			total = 0
		}
		if total > 0 && lastTotal > 0 && total != lastTotal {
			// 页总数在复制期间变化说明 SQLite 重启了备份（源库被其它连接修改
			// 且无法继续使用同一快照）。允许有限次重启，持续重启则有界失败。
			restarts++
			if restarts > maxBackupRestarts {
				return storage.New(storage.ErrBusy, "数据库持续写入导致在线备份多次重启，请稍后重试", nil)
			}
		}
		if total > 0 {
			lastTotal = total
		}
		if progress != nil {
			progress(done, total)
		}
		if !more {
			break
		}
	}
	// 最后一页复制完成后、提交释放备份句柄前再检查一次取消：调用方可能在进度
	// 回调中取消，此时不能把已取消的备份报告为成功。
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := backup.Finish(); err != nil {
		return mapError(err)
	}
	finished = true
	return nil
}
