package setupconsole

// WS3 写入门控与维护日志：只读操作不取实例维护写门（主服务运行时可浏览），
// 写操作必须同时满足：
//   - 281 排他锁/主服务检测的 WriteGuard（失败 fail-closed）；
//   - 维护日志可写（WS1 MaintLog；记录 operator/instance/action/target/result）。
// 日志不可写时阻止关键身份修改（NO-1 LOW-1）。读取方法由嵌入接口原样转发。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// localWriteGuard 与 LocalRuntimeOptions.WriteGuard 相同：获取成功返回释放函数。
type localWriteGuard func(context.Context) (func(), error)

// ws3MaintRecorder 把维护日志与维护身份绑定；nil 表示日志不可用（写操作拒绝）。
type ws3MaintRecorder struct {
	log         MaintLog
	identity    MaintenanceIdentity
	instanceDir string
}

func newWS3MaintRecorder(instanceDir string) (*ws3MaintRecorder, error) {
	identity, err := LocalMaintenanceIdentity(instanceDir)
	if err != nil {
		return nil, err
	}
	log, err := OpenMaintenanceLog(instanceDir)
	if err != nil {
		return nil, err
	}
	return &ws3MaintRecorder{log: log, identity: identity, instanceDir: instanceDir}, nil
}

// operationID 生成本地维护操作 ID（op_ + 随机 hex）。
func ws3OperationID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "op_" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return "op_" + hex.EncodeToString(raw[:])
}

// record 追加维护日志；失败返回错误（调用方必须阻止写操作）。
func (m *ws3MaintRecorder) record(ctx context.Context, operationID, action, target,
	result, errorCode string, started, finished time.Time) error {
	if m == nil || m.log == nil {
		return fmt.Errorf("维护日志不可用，写操作被拒绝")
	}
	_, err := m.log.Record(ctx, MaintLogEntry{OperationID: operationID,
		Identity: m.identity, InstanceDir: m.instanceDir, Action: action,
		Target: target, Result: result, ErrorCode: errorCode,
		StartedAt: started, FinishedAt: finished})
	if err != nil {
		return fmt.Errorf("维护日志不可写，写操作被拒绝: %w", err)
	}
	return nil
}

// acquireLocalWrite 获取写门；nil 门表示未接锁（M1 前本地入口），直接放行。
func acquireLocalWrite(ctx context.Context, guard localWriteGuard) (func(), error) {
	if guard == nil {
		return func() {}, nil
	}
	release, err := guard(ctx)
	if err != nil {
		return nil, fmt.Errorf("实例正在运行或维护锁不可用，写操作被拒绝：%w", err)
	}
	if release == nil {
		release = func() {}
	}
	return release, nil
}

// runMaintWrite 在写门与维护日志下执行一次写操作：
//   - 维护日志不可用 → 写操作不执行（fail-closed）；
//   - 先记录 "started"（失败则不执行），再获取写门；写门拒绝也记录 "failed"，
//     保证危险动作尝试有独立维护证据；
//   - 业务失败记录 "failed"（不掩盖业务错误）；
//   - 业务成功但终态日志失败 → 返回错误（写操作已发生，明确提示审计缺口）。
func runMaintWrite(ctx context.Context, guard localWriteGuard, maint *ws3MaintRecorder,
	action, target string, fn func() error) error {
	operationID := ws3OperationID()
	started := time.Now().UTC()
	if err := maint.record(ctx, operationID, action, target, "started", "", started, started); err != nil {
		return err
	}
	release, err := acquireLocalWrite(ctx, guard)
	if err != nil {
		finished := time.Now().UTC()
		_ = maint.record(ctx, operationID, action, target, "failed", "WRITE_GUARD_DENIED",
			started, finished)
		return err
	}
	defer release()
	businessErr := fn()
	finished := time.Now().UTC()
	result := "success"
	errorCode := ""
	if businessErr != nil {
		result = "failed"
		errorCode = "WRITE_FAILED"
	}
	if recordErr := maint.record(ctx, operationID, action, target, result, errorCode,
		started, finished); recordErr != nil {
		if businessErr != nil {
			return businessErr
		}
		return fmt.Errorf("操作已提交但维护日志终态记录失败: %w", recordErr)
	}
	return businessErr
}

// withWriteResult 在写门+维护日志下执行有返回值操作。
func withWriteResult[T any](ctx context.Context, guard localWriteGuard,
	maint *ws3MaintRecorder, action, target string, fn func() (T, error)) (T, error) {
	var value T
	err := runMaintWrite(ctx, guard, maint, action, target, func() error {
		result, businessErr := fn()
		if businessErr != nil {
			return businessErr
		}
		value = result
		return nil
	})
	return value, err
}

// withWrite 在写门+维护日志下执行无返回值/仅错误操作。
func withWrite(ctx context.Context, guard localWriteGuard, maint *ws3MaintRecorder,
	action, target string, fn func() error) error {
	return runMaintWrite(ctx, guard, maint, action, target, fn)
}

// maintTarget 构造日志目标（不包含秘密/自由文本中的敏感词）。
func maintTarget(kind, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return kind
	}
	lower := strings.ToLower(id)
	for _, forbidden := range []string{"password", "secret", "token="} {
		if strings.Contains(lower, forbidden) {
			return kind
		}
	}
	return kind + ":" + ws3Truncate(id, 96)
}

// guardedUserAdmin 只覆写用户写方法，读取方法由嵌入接口转发。
type guardedUserAdmin struct {
	UserAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedUserAdmin) CreateUser(ctx context.Context,
	input LocalUserCreate) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.create", "user:new",
		func() (LocalUser, error) {
			return g.UserAdmin.CreateUser(ctx, input)
		})
}

func (g guardedUserAdmin) UpdateProfile(ctx context.Context, userID string,
	input LocalProfileUpdate) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.profile", maintTarget("user", userID),
		func() (LocalUser, error) {
			return g.UserAdmin.UpdateProfile(ctx, userID, input)
		})
}

func (g guardedUserAdmin) SetEnabled(ctx context.Context, userID string, enabled bool,
	expectedRowVersion int64) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.state", maintTarget("user", userID),
		func() (LocalUser, error) {
			return g.UserAdmin.SetEnabled(ctx, userID, enabled, expectedRowVersion)
		})
}

func (g guardedUserAdmin) SetValidity(ctx context.Context, userID string,
	validity LocalValidity) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.validity", maintTarget("user", userID),
		func() (LocalUser, error) {
			return g.UserAdmin.SetValidity(ctx, userID, validity)
		})
}

func (g guardedUserAdmin) RequestDeletion(ctx context.Context, userID string,
	expectedRowVersion int64) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.delete_prepare",
		maintTarget("user", userID), func() (LocalUser, error) {
			return g.UserAdmin.RequestDeletion(ctx, userID, expectedRowVersion)
		})
}

func (g guardedUserAdmin) CompleteDeletion(ctx context.Context, userID string,
	expectedRowVersion int64) (LocalDeletionPreview, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.delete_complete",
		maintTarget("user", userID), func() (LocalDeletionPreview, error) {
			return g.UserAdmin.CompleteDeletion(ctx, userID, expectedRowVersion)
		})
}

func (g guardedUserAdmin) AssignRole(ctx context.Context, userID, roleID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.user.role.assign", maintTarget("user", userID),
		func() error {
			return g.UserAdmin.AssignRole(ctx, userID, roleID)
		})
}

// guardedIdentityAdmin 覆写改名/设密。
type guardedIdentityAdmin struct {
	IdentityAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedIdentityAdmin) Rename(ctx context.Context, userID, newUsername, reason string,
	expectedRowVersion int64) (LocalUser, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.user.rename",
		maintTarget("user", userID), func() (LocalUser, error) {
			return g.IdentityAdmin.Rename(ctx, userID, newUsername, reason, expectedRowVersion)
		})
}

func (g guardedIdentityAdmin) SetPassword(ctx context.Context, userID, newPassword string,
	requireChange bool) (LocalPasswordResult, error) {
	// 目标只记录稳定用户 ID；新密码永不进入日志（recorder target 校验也会拒绝）。
	return withWriteResult(ctx, g.guard, g.maint, "ws3.credential.set",
		maintTarget("user", userID), func() (LocalPasswordResult, error) {
			return g.IdentityAdmin.SetPassword(ctx, userID, newPassword, requireChange)
		})
}

// guardedSecurityAdmin 覆写因素/恢复代码/会话写方法。
type guardedSecurityAdmin struct {
	SecurityAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedSecurityAdmin) RemoveFactor(ctx context.Context, userID string,
	factor LocalFactor, reason string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.mfa.factor.remove",
		maintTarget("user", userID), func() error {
			return g.SecurityAdmin.RemoveFactor(ctx, userID, factor, reason)
		})
}

func (g guardedSecurityAdmin) RevokeRecoveryCodes(ctx context.Context, userID, reason string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.recovery.codes.revoke",
		maintTarget("user", userID), func() error {
			return g.SecurityAdmin.RevokeRecoveryCodes(ctx, userID, reason)
		})
}

func (g guardedSecurityAdmin) ClearSecondFactors(ctx context.Context, userID string,
	includePrimaryPasskeys bool, reason string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.mfa.clear",
		maintTarget("user", userID), func() error {
			return g.SecurityAdmin.ClearSecondFactors(ctx, userID, includePrimaryPasskeys, reason)
		})
}

func (g guardedSecurityAdmin) RevokeSessions(ctx context.Context, userID,
	reason string) (int64, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.session.revoke",
		maintTarget("user", userID), func() (int64, error) {
			return g.SecurityAdmin.RevokeSessions(ctx, userID, reason)
		})
}

// guardedRBACAdmin 覆写角色/组/预设恢复写方法。
type guardedRBACAdmin struct {
	RBACAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedRBACAdmin) RestorePreset(ctx context.Context, diff LocalPresetDiff,
	confirm bool) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.preset.restore", "scope:"+diff.ScopeID,
		func() error {
			return g.RBACAdmin.RestorePreset(ctx, diff, confirm)
		})
}

func (g guardedRBACAdmin) SetRoleEnabled(ctx context.Context, roleID string, enabled bool) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.role.state", maintTarget("role", roleID),
		func() error {
			return g.RBACAdmin.SetRoleEnabled(ctx, roleID, enabled)
		})
}

func (g guardedRBACAdmin) AddGroupMember(ctx context.Context, groupID, userID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.group.member.add",
		maintTarget("group", groupID), func() error {
			return g.RBACAdmin.AddGroupMember(ctx, groupID, userID)
		})
}

func (g guardedRBACAdmin) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.group.member.remove",
		maintTarget("group", groupID), func() error {
			return g.RBACAdmin.RemoveGroupMember(ctx, groupID, userID)
		})
}

// guardedAppAdmin 覆写应用/成员/客户端凭证写方法。
type guardedAppAdmin struct {
	AppAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedAppAdmin) CreateApplication(ctx context.Context, name, description,
	homepage string) (LocalApplication, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.app.create", "app:new",
		func() (LocalApplication, error) {
			return g.AppAdmin.CreateApplication(ctx, name, description, homepage)
		})
}

func (g guardedAppAdmin) UpdateApplication(ctx context.Context, applicationID, name,
	description, homepage string, expectedRowVersion int64) (LocalApplication, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.app.profile",
		maintTarget("app", applicationID), func() (LocalApplication, error) {
			return g.AppAdmin.UpdateApplication(ctx, applicationID, name, description, homepage,
				expectedRowVersion)
		})
}

func (g guardedAppAdmin) SetApplicationEnabled(ctx context.Context, applicationID string,
	enabled bool) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.app.state",
		maintTarget("app", applicationID), func() error {
			return g.AppAdmin.SetApplicationEnabled(ctx, applicationID, enabled)
		})
}

func (g guardedAppAdmin) AddMember(ctx context.Context, applicationID, userID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.app.member.add",
		maintTarget("app", applicationID), func() error {
			return g.AppAdmin.AddMember(ctx, applicationID, userID)
		})
}

func (g guardedAppAdmin) RemoveMember(ctx context.Context, applicationID, userID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.app.member.remove",
		maintTarget("app", applicationID), func() error {
			return g.AppAdmin.RemoveMember(ctx, applicationID, userID)
		})
}

func (g guardedAppAdmin) CreateClient(ctx context.Context, applicationID, name string,
	redirectURIs []string) (LocalAppClientCreated, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.oauth.client.register",
		maintTarget("app", applicationID), func() (LocalAppClientCreated, error) {
			return g.AppAdmin.CreateClient(ctx, applicationID, name, redirectURIs)
		})
}

func (g guardedAppAdmin) RotateClientSecret(ctx context.Context, applicationID,
	clientID string) (LocalAppClientCreated, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.oauth.client.rotate",
		maintTarget("app", applicationID), func() (LocalAppClientCreated, error) {
			return g.AppAdmin.RotateClientSecret(ctx, applicationID, clientID)
		})
}

func (g guardedAppAdmin) RevokeClient(ctx context.Context, applicationID, clientID string) error {
	return withWrite(ctx, g.guard, g.maint, "ws3.oauth.client.revoke",
		maintTarget("app", applicationID), func() error {
			return g.AppAdmin.RevokeClient(ctx, applicationID, clientID)
		})
}

// guardedAuditAdmin 覆写任务取消（审计查询/诊断/列表为只读，不取写门）。
type guardedAuditAdmin struct {
	AuditAdmin
	guard localWriteGuard
	maint *ws3MaintRecorder
}

func (g guardedAuditAdmin) CancelTask(ctx context.Context, taskID,
	reason string) (LocalTask, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.task.cancel",
		maintTarget("task", taskID), func() (LocalTask, error) {
			return g.AuditAdmin.CancelTask(ctx, taskID, reason)
		})
}

// SetRetention 是危险审计写：必须经写门+维护日志。
func (g guardedAuditAdmin) SetRetention(ctx context.Context, retentionDays int,
	reason string) (LocalRetention, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.audit.retention", "audit:system",
		func() (LocalRetention, error) {
			return g.AuditAdmin.SetRetention(ctx, retentionDays, reason)
		})
}

// StartPurge 是危险审计清理提交：必须经写门+维护日志。
func (g guardedAuditAdmin) StartPurge(ctx context.Context, preview LocalPurgePreview,
	reason string) (LocalPurgeRun, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.audit.purge.start",
		maintTarget("audit", preview.ScopeID), func() (LocalPurgeRun, error) {
			return g.AuditAdmin.StartPurge(ctx, preview, reason)
		})
}

// GenerateReport 创建报告任务（受控导出面）：必须经写门+维护日志。
func (g guardedAuditAdmin) GenerateReport(ctx context.Context,
	request LocalReportRequest) (LocalReport, error) {
	return withWriteResult(ctx, g.guard, g.maint, "ws3.report.generate",
		maintTarget("report", request.ScopeID), func() (LocalReport, error) {
			return g.AuditAdmin.GenerateReport(ctx, request)
		})
}
