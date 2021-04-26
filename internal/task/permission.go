package task

import (
	"context"
	"encoding/json"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// PermissionRequest 是运行前权限复验的输入。Actor 是计划或任务记录的执行身份，
// Kind/Payload/MutexKey 来自计划或任务本身；本包不解析具体权限模型，只把可信
// 回调的结论当作唯一授权依据。
type PermissionRequest struct {
	// Kind 是目标任务类型。
	Kind string
	// Actor 是执行身份（计划的 ExecutionActor 或任务的 Initiator）。
	Actor audit.Actor
	// Payload 是任务载荷的副本，回调不得修改。
	Payload json.RawMessage
	// MutexKey 是任务互斥键。
	MutexKey string
	// ScheduleID 是计划编号；直接入队的任务为空。
	ScheduleID string
	// JobID 是已创建任务编号；计划触发前为空。
	JobID string
}

// PermissionCheck 是调用方注入的可信权限复验回调。返回 nil 表示当前仍有权限；
// 返回任何错误表示拒绝执行，调用方必须默认拒绝，不得把错误当作放行。
//
// 本包不提供默认放行的实现：计划要求权限复验而回调缺失时，计划触发与任务执行
// 都会失败（fail-closed），由审计记录拒绝原因。
type PermissionCheck func(ctx context.Context, request PermissionRequest) error
