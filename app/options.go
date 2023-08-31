package app

import (
	"log/slog"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
)

// Options 是嵌入式装配参数。Config 与 ConfigPath 二选一；两者同时提供时使用 Config。
//
// 生命周期：Open 只构造运行时（不监听端口、不启动后台任务）；后台任务必须由宿主
// 显式调用 Runtime.Start 启动。宿主注入的 Logger、Database、Notifier 由宿主拥有，
// 运行时只使用、绝不关闭。
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
	// Database 是宿主拥有的数据库就绪检查依赖（可选）。运行时只在 Ready 时调用
	// Ping，绝不关闭它；宿主可以在多个运行时之间共享同一连接。
	Database login.Database
	// Notifier 是宿主拥有的生命周期通知器（可选）。Start/Close 事件在实例锁外
	// 以有界超时发送；通知失败只写运行日志，不改变生命周期结果。运行时不关闭它。
	Notifier login.Notifier
	// HTTP 是嵌入式 HTTP 与页面挂载选项；nil 表示不装配 HTTP（只使用 Go API）。
	// 设置后 Open 会装配与独立服务相同的协议域/页面/管理 API/HTTP 防护链；宿主
	// 用自己的 http.Server 监听，并通过 Runtime.Handler/Mount 挂载。缺少依赖或
	// 配置非法时 Open 失败，不会只提供健康页。
	HTTP *HTTPOptions
}
