package app

import (
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// Options 是嵌入式装配参数。Config 与 ConfigPath 二选一；两者同时提供时使用 Config。
type Options struct {
	Config          *login.Config
	ConfigPath      string
	DatabasePath    string
	MasterKeyFile   string
	CreateMasterKey bool
	Migrate         bool
	Logger          *slog.Logger
	Now             func() time.Time
	// OperatorID 是本地受信操作者标识（root 初始化/用户创建审计），必填。
	OperatorID string
}
