package sqlserver

import (
	"context"
	"errors"
	"fmt"
)

// ErrOnlineBackupUnsupported 表示 SQL Server 在线备份能力未实现。它不是“暂时失败”，
// 而是本版本明确不支持；调用方不得把它当作可重试错误，也不得据此生成空备份。
var ErrOnlineBackupUnsupported = errors.New("SQL Server 在线备份未实现")

// BackupCapability 描述 SQL Server 后端的备份/恢复能力边界。宿主可据此显示状态、
// 禁用按钮并提示运维使用外部受控机制。
type BackupCapability struct {
	// Supported 永远为 false（本版本）。不得为了界面好看改成 true。
	Supported bool
	// Mechanism 说明设计上应采用的一致性机制（尚未实现/未验证）。
	Mechanism string
	// Limitation 是本版本的真实限制。
	Limitation string
	// RequiredTools 是未来实现所需的受控外部工具（版本未验证，不作为依赖引入）。
	RequiredTools []string
	// Unverified 列出未运行验证的范围。
	Unverified string
}

// BackupCapability 返回 SQL Server 后端的备份能力声明。SQLite 的 modernc 在线快照
// 机制与 SQL Server 的 BACKUP DATABASE 机制不同；在实现并验证外部一致性备份之前，
// 明确声明不支持，不返回空备份冒充成功。
func (s *Store) BackupCapability() BackupCapability {
	return BackupCapability{
		Supported: false,
		Mechanism: "需要基于 SQL Server 一致性备份机制的受控外部流程（BACKUP DATABASE ... WITH COPY_ONLY" +
			"/CHECKSUM 或托管快照），并与配置/密钥/附件清单绑定同一时间点",
		Limitation: "本版本未实现 SQL Server 在线备份：不执行 BACKUP DATABASE、不复制数据文件、" +
			"不返回空备份、不声称可恢复；备份相关页面与 CLI 必须按不支持处理",
		RequiredTools: []string{"sqlcmd 或等效受控管理通道（版本未验证）", "SQL Server BACKUP DATABASE 权限与目标存储（未引入依赖、未验证）"},
		Unverified:    "未启动 SQL Server，未验证任何一致性备份/校验/恢复流程；恢复代际与库外审计锚点也未接入 SQL Server",
	}
}

// CreateOnlineBackup 明确拒绝 SQL Server 在线备份。它不会创建文件、不会返回成功。
func (s *Store) CreateOnlineBackup(ctx context.Context, target string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("%w：不生成假备份，请使用受控的外部一致性备份流程并另行实现校验与恢复", ErrOnlineBackupUnsupported)
}

// RestoreOnlineBackup 明确拒绝 SQL Server 在线恢复，避免误以为已具备与 SQLite 相同
// 的维护模式恢复能力。
func (s *Store) RestoreOnlineBackup(ctx context.Context, source string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("%w：SQL Server 恢复流程未实现，禁止在维护模式之外尝试替换数据库", ErrOnlineBackupUnsupported)
}
