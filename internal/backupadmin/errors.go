// Package backupadmin 把步骤 80 的一致性加密备份服务接入 internal/task 调度与管理
// 页面所需的领域能力（步骤 81）：定时备份计划、持久任务与真实阶段/进度、保留策略
// 与受保护的产物清理、独立授权下载、取消、失败/成功通知与孤儿产物对账。
//
// 安全不变量：
//   - 页面/宿主只能通过本包公开的 Service 方法操作；每个读取与写入都重新调用注入
//     的 Authorizer 复核权限与系统范围，读取列表不等于可下载、可取消或可清理。
//   - 创建备份、下载备份、修改保留策略与执行清理分别要求独立权限，并按
//     internal/policy 敏感操作目录接入注入的 reauth.OperationRunner（强认证 + 确认）；
//     执行器不可用时按拒绝处理，绝不静默放行。
//   - 任务状态以 internal/task 的持久状态机为唯一事实源；本包只记录受控阶段/进度与
//     通知投递结果，不复制或伪造状态。取消请求被接受不等于任务已取消。
//   - 清理只删除受控输出目录中的备份成品并更新受控元数据，不删除原始安全审计；
//     原始审计清理仍由步骤 74 的 root 专属流程负责。最后一份可用备份与校验状态未知
//     的产物受保护，失败的新备份不会使旧可用备份失去保护；清理在执行时重新计算候选
//     与保护状态，不按旧预览强删。
//   - 通知失败只记录通知自身结果；备份产物、校验状态与历史记录不受影响。
//   - 本包不启动常驻协程、不监听端口、不提供 HTTP 路由；任务处理器由宿主注册到
//     internal/task Executor，调度器与执行器的启动/停止由宿主决定。
package backupadmin

import (
	"errors"

	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
)

// 领域错误哨兵。对外只通过 CodeOf 映射为根包既有错误码，不新增错误码。
var (
	// ErrOptionsInvalid 表示依赖或配置非法（fail-closed）。
	ErrOptionsInvalid = backup.ErrOptionsInvalid
	// ErrInvalidRequest 表示请求参数非法。
	ErrInvalidRequest = backup.ErrInvalidRequest
	// ErrAccessDenied 表示未获准执行该操作（含范围不符与敏感操作未通过）。
	ErrAccessDenied = backup.ErrAccessDenied
	// ErrAuditUnavailable 表示关键审计不可用，操作拒绝或回滚。
	ErrAuditUnavailable = backup.ErrAuditUnavailable
	// ErrStoreUnavailable 表示持久化暂时不可用。
	ErrStoreUnavailable = backup.ErrStoreUnavailable
	// ErrNotFound 表示对象不存在或当前范围不可见；对外不区分不存在与无权。
	ErrNotFound = errors.New("备份对象不存在或当前范围不可见")
	// ErrConflict 表示状态、行版本或目标集已变化，需要重新读取；不做静默覆盖。
	ErrConflict = errors.New("备份对象状态或版本已变化")
	// ErrRetentionInvalid 表示保留策略取值非法（含三项全部不启用）。
	ErrRetentionInvalid = errors.New("备份保留策略无效")
	// ErrProtection 表示目标受最后可用/未知状态保护，拒绝清理。
	ErrProtection = errors.New("备份产物受保护，不能清理")
	// ErrDownloadTooLarge 表示产物超过浏览下载上限；不把大文件读入内存或截断。
	ErrDownloadTooLarge = errors.New("备份产物超过页面下载上限，请使用受控本地路径")
	// ErrNotDownloadable 表示产物未通过校验、已清理或文件缺失，不能按正常备份下载。
	ErrNotDownloadable = errors.New("该备份当前不可下载")
)

// CodeOf 把备份管理域错误映射为根包已登记错误码（不新增错误码）。
func CodeOf(err error) backup.ErrorCode {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrRetentionInvalid):
		return backup.CodeReqInvalid
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrNotFound):
		// 不存在与无权对外统一为 ACCESS_DENIED，避免枚举其他对象。
		return backup.CodeAccessDenied
	case errors.Is(err, ErrConflict), errors.Is(err, ErrProtection):
		return backup.CodeConflict
	case errors.Is(err, backup.ErrCancelConflict):
		return backup.CodeTaskCancelConflict
	case errors.Is(err, backup.ErrCancelled):
		return backup.CodeTaskCancelled
	case errors.Is(err, backup.ErrTimeout):
		return backup.CodeTaskTimeout
	default:
		return backup.CodeOf(err)
	}
}
