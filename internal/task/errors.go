package task

import "errors"

// 本包错误只说明失败类别，不包含任务载荷、处理器错误原文或数据库细节。对外
// 错误码映射由后续服务层完成（TASK_CANCEL_CONFLICT、TASK_CANCELLED、
// TASK_TIMEOUT、INTERNAL_ERROR 等）。
var (
	// ErrInvalidRequest 表示入队/取消/查询参数不合法。
	ErrInvalidRequest = errors.New("task: 请求参数无效")
	// ErrUntrustedActor 表示调用者不是可信操作者（匿名或无效身份），禁止入队与
	// 取消；本包不提供匿名远程端点。
	ErrUntrustedActor = errors.New("task: 不可信操作者")
	// ErrTaskNotFound 表示任务不存在。
	ErrTaskNotFound = errors.New("task: 任务不存在")
	// ErrTaskTerminal 表示任务已经进入终态，晚到的取消请求被拒绝；取消请求被
	// 接受不等于任务已取消。
	ErrTaskTerminal = errors.New("task: 任务已进入终态，取消被拒绝")
	// ErrTransitionRejected 表示条件状态更新没有命中，通常是并发完成/取消竞争；
	// 调用方必须读取真实状态，不能把取消请求显示为已取消。
	ErrTransitionRejected = errors.New("task: 任务状态转换被拒绝")
	// ErrStoreUnavailable 表示任务存储不可用；状态变化没有提交。
	ErrStoreUnavailable = errors.New("task: 任务存储不可用")
	// ErrOptionsInvalid 表示执行器构造选项不合法。
	ErrOptionsInvalid = errors.New("task: 执行器选项无效")
	// ErrAlreadyStarted 表示执行器已经启动，不能重复启动。
	ErrAlreadyStarted = errors.New("task: 执行器已经启动")
	// ErrClosed 表示执行器已经停止，不能再次启动。
	ErrClosed = errors.New("task: 执行器已经停止")
	// ErrShutdownTimeout 表示执行器在期限内未能等待所有处理器退出；调用方应
	// 视为仍有残留资源并以重启恢复策略处理，不得声称已完全清理。
	ErrShutdownTimeout = errors.New("task: 执行器关闭超时")
	// ErrRecoveryFailed 表示启动时遗留任务恢复失败，执行器拒绝开始领取新任务。
	ErrRecoveryFailed = errors.New("task: 遗留任务恢复失败")
	// ErrInternalRandomSource 表示安全随机源不可用，无法生成任务编号。
	ErrInternalRandomSource = errors.New("task: 安全随机源不可用")
	// ErrScheduleNotFound 表示计划不存在。
	ErrScheduleNotFound = errors.New("task: 定时计划不存在")
	// ErrScheduleForbidden 表示调用者既不是计划所有者，也不是系统或本地管理员，
	// 不能暂停、恢复或删除该计划；服务层仍必须先完成自己的授权检查。
	ErrScheduleForbidden = errors.New("task: 调用者不能修改该计划")
	// ErrPermissionCheckRequired 表示计划要求运行前权限复验但没有配置可信回调；
	// 管理类计划不得在缺少权限校验时默认放行。
	ErrPermissionCheckRequired = errors.New("task: 缺少必要的权限复验回调")
	// ErrPermissionRevoked 表示运行前权限复验拒绝执行；任务不重试并记录安全原因。
	ErrPermissionRevoked = errors.New("task: 运行前权限复验未通过")
)
