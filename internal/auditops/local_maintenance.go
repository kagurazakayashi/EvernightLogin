package auditops

// 步骤 291（本地维护控制台）：审计保留策略与危险清理的本地维护窄方法。
//
// 普通入口要求 root + audit.purge 敏感策略；本地维护控制台以 OS 访问权限执行显式
// 危险动作，不要求 Evernight root 账户/近期认证，但：
//   - 显式 LocalMaintenanceCaller（不可 JSON 反序列化、仅本机 login-setup 装配）；
//   - 复用同一保留策略/清理预估/异步清理/受保护清理日志实现（不建第二套清理）；
//   - 每次危险动作仍写受保护清理日志与审计事件；“本次维护证据”位于维护日志，
//     清理自身不会删除该日志（MaintenanceProtected 语义由既有实现保证）；
//   - 维护锁/主服务检测由调用方（setupconsole 写门）保证；本包只执行领域动作。

import (
	"context"
	"fmt"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// LocalMaintenanceCaller 是仅供本机维护控制台使用的显式本地身份。
type LocalMaintenanceCaller struct {
	operatorID string
}

// NewLocalMaintenanceCaller 构造本地维护身份；只应由 cmd/login-setup（经
// internal/setupconsole）调用，不代表 Evernight 账户/HTTP 身份。
func NewLocalMaintenanceCaller(operatorID string) (LocalMaintenanceCaller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return LocalMaintenanceCaller{}, fmt.Errorf("%w: 本地维护操作者标识无效", ErrInvalidRequest)
	}
	return LocalMaintenanceCaller{operatorID: operatorID}, nil
}

// OperatorID 返回审计用本地操作者标识。
func (c LocalMaintenanceCaller) OperatorID() string { return c.operatorID }

func (s *Service) localMaintenanceAccountCaller(caller LocalMaintenanceCaller) (account.Caller, error) {
	if caller.operatorID == "" {
		return account.Caller{}, ErrAccessDenied
	}
	return account.LocalBootstrapCaller(caller.operatorID)
}

// LocalMaintenanceRetention 读取保留策略（只读，运维信息）。
func (s *Service) LocalMaintenanceRetention(ctx context.Context) (RetentionInfo, error) {
	return s.retentionInfo(ctx)
}

// LocalMaintenanceSetRetention 设置保留策略（本地危险动作；仍写受保护清理日志+
// 审计，版本 CAS 与范围校验同普通路径）。
func (s *Service) LocalMaintenanceSetRetention(ctx context.Context,
	caller LocalMaintenanceCaller, retentionDays int, reason, requestID string,
	expectedVersion int64) (RetentionInfo, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return RetentionInfo{}, err
	}
	return s.setRetentionInternal(ctx, SetRetentionRequest{Caller: accountCaller,
		RetentionDays: retentionDays, Reason: reason, RequestID: requestID,
		ExpectedVersion: expectedVersion}, true)
}

// LocalMaintenancePreviewPurge 生成清理预估（只读，不删除记录）。
func (s *Service) LocalMaintenancePreviewPurge(ctx context.Context,
	caller LocalMaintenanceCaller, scopeID string, cutoff time.Time, batchSize, maxRecords int,
	requestID string) (PurgePreview, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return PurgePreview{}, err
	}
	return s.previewPurgeInternal(ctx, PurgePreviewRequest{Caller: accountCaller,
		ScopeID: scopeID, Cutoff: cutoff, BatchSize: batchSize, MaxRecords: maxRecords,
		RequestID: requestID}, true)
}

// LocalMaintenanceStartPurge 提交显式清理任务（异步执行；维护日志与清理记录由
// 既有实现保护，不随被清理历史一起删除）。
func (s *Service) LocalMaintenanceStartPurge(ctx context.Context,
	caller LocalMaintenanceCaller, scopeID string, cutoff time.Time, batchSize, maxRecords int,
	reason, digest, requestID string) (PurgeRunView, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return PurgeRunView{}, err
	}
	return s.startPurgeInternal(ctx, StartPurgeRequest{Caller: accountCaller,
		ScopeID: scopeID, Cutoff: cutoff, BatchSize: batchSize, MaxRecords: maxRecords,
		Reason: reason, Digest: digest, RequestID: requestID}, true)
}

// LocalMaintenanceListPurgeRuns 列出清理运行（只读维护证据）。
func (s *Service) LocalMaintenanceListPurgeRuns(ctx context.Context,
	caller LocalMaintenanceCaller, kind, state string, limit, offset int) (
	[]PurgeRunView, bool, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return nil, false, err
	}
	return s.listPurgeRunsInternal(ctx, PurgeListRequest{Caller: accountCaller,
		Kind: kind, State: state, Limit: limit, Offset: offset}, true)
}

// LocalMaintenanceGetPurgeRun 读取单次清理运行。
func (s *Service) LocalMaintenanceGetPurgeRun(ctx context.Context,
	caller LocalMaintenanceCaller, runID string) (PurgeRunView, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return PurgeRunView{}, err
	}
	return s.getPurgeRunInternal(ctx, accountCaller, runID, true)
}

// LocalMaintenanceLog 读取某次清理的受保护维护证据。
func (s *Service) LocalMaintenanceLog(ctx context.Context,
	caller LocalMaintenanceCaller, runID string) ([]MaintenanceEntry, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return nil, err
	}
	return s.maintenanceLogInternal(ctx, accountCaller, runID, true)
}

// LocalMaintenanceCancelPurge 请求取消清理任务（提交取消≠实际取消，终态以任务
// 与运行状态为准）。
func (s *Service) LocalMaintenanceCancelPurge(ctx context.Context,
	caller LocalMaintenanceCaller, runID, reason, requestID string) (task.CancelResult, error) {
	accountCaller, err := s.localMaintenanceAccountCaller(caller)
	if err != nil {
		return task.CancelResult{}, err
	}
	return s.cancelPurgeInternal(ctx, accountCaller, runID, reason, requestID, true)
}
