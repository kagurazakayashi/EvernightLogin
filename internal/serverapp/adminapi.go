package serverapp

// 管理 JSON API 集成：把 internal/adminapi 挂载到独立服务。
//
// 边界：
//   - 认证复用真实 session.Service（ManagementSession：每次请求重新
//     AuthorizeManagement，要求已完成强认证且在新鲜度窗口内）；
//   - CSRF 复用会话绑定令牌契约（Cookie 会话的写请求必须带 X-CSRF-Token）；
//   - 默认关闭：只有显式 --enable-admin-api 才挂载；未启用时请求得到 404；
//   - 维护模式不挂载任何管理 API（只放行健康检查，其余 503）；
//   - 只挂载已装配的领域服务路由：当前任务详情（读）可用；审计/报告/备份服务
//     未装配，其路由不挂载（404，不伪造成功）；
//   - 错误码投影来自根包注册表，缺码时构造失败（fail-closed）。

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// ReservedAdminAPIConflicts 是管理 API 前缀不允许覆盖的页面命名空间根。
// 允许挂在它们之下（例如默认 /admin/v1 与页面 /admin/users 不重叠），但不允许
// 与根同名或成为页面的祖先前缀（会遮蔽页面路由）。
var ReservedAdminAPIConflicts = []string{
	"/login", "/register", "/home", "/admin", "/mfa", "/oauth", "/consent",
	"/security", "/support", "/logout", "/invite", "/verify-email",
}

// BuildAdminAPIServer 构造管理 JSON API 处理程序。
//
// prefix 为空时使用 adminapi.DefaultBasePath；非法前缀、缺少会话/任务依赖、
// 错误码投影缺失时报错（启动失败），不降级为“匿名可读”。
func BuildAdminAPIServer(deps Deps, services *Services, managed *ManagedServices,
	runtime *TaskRuntime, pages *Pages, prefix string, gate *SecurityGate) (http.Handler, string, error) {
	if gate == nil || gate.Reauth == nil {
		return nil, "", fmt.Errorf("管理 API 缺少敏感操作闸门")
	}
	if services == nil || services.Sessions == nil {
		return nil, "", fmt.Errorf("管理 API 缺少真实会话服务")
	}
	if managed == nil || managed.Checker == nil {
		return nil, "", fmt.Errorf("管理 API 缺少生产授权适配层")
	}
	if runtime == nil || runtime.Executor() == nil {
		return nil, "", fmt.Errorf("管理 API 缺少任务执行器")
	}
	normalized, err := normalizeAdminAPIPrefix(prefix)
	if err != nil {
		return nil, "", err
	}
	codes := make([]adminapi.ErrorCodeInfo, 0, len(login.RegisteredErrorCodes()))
	for _, definition := range login.RegisteredErrorCodes() {
		codes = append(codes, adminapi.ErrorCodeInfo{
			Code: string(definition.Code), Message: definition.DefaultMessage,
			HTTPStatus: definition.HTTPStatus,
		})
	}
	server, err := adminapi.New(adminapi.Options{
		BasePath: normalized,
		// 会话校验仍走真实 session.Service；包装器额外登记本次请求的管理强认证
		// 事实，供同一请求内的高风险权限目录动作再次认证使用（步骤 189）。
		Session:        managementSessionRecorder{Service: services.Sessions, gate: gate},
		ErrorCodes:     codes,
		Tasks:          runtime.Executor(),
		TaskAuthorizer: hostTaskAuthorizer{checker: managed.Checker},
		// 已装配的真实领域服务：审计查询/导出/清理、报告与计划、备份管理。
		Audit:         managed.AuditOps,
		Reports:       managed.Reports,
		Plans:         managed.Plans,
		Backups:       managed.BackupAdmin,
		Sensitive:     gate.Reauth,
		Notifications: newMailNotificationService(deps.Mail, runtime),
		DomainRoutes:  buildAdminDomainRoutes(managed, pages, gate),
		AuditRecorder: deps.Audit,
		Logger:        deps.Logger, Now: deps.Now,
	})
	if err != nil {
		return nil, "", fmt.Errorf("构造管理 API 失败: %w", err)
	}
	return server, normalized, nil
}

// normalizeAdminAPIPrefix 校验并返回管理 API 挂载前缀。
func normalizeAdminAPIPrefix(prefix string) (string, error) {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		trimmed = adminapi.DefaultBasePath
	}
	if !strings.HasPrefix(trimmed, "/") || trimmed == "/" ||
		strings.HasSuffix(trimmed, "/") || strings.Contains(trimmed, "//") {
		return "", fmt.Errorf("管理 API 前缀必须以 / 开头且不能以 / 结尾或包含重复斜杠")
	}
	for _, reserved := range ReservedAdminAPIConflicts {
		if trimmed == reserved || strings.HasPrefix(reserved, trimmed+"/") {
			return "", fmt.Errorf("管理 API 前缀 %s 覆盖页面命名空间 %s", trimmed, reserved)
		}
	}
	return trimmed, nil
}

// hostTaskAuthorizer 实现 adminapi.TaskAuthorizer：任务详情读取需要功能权限。
type hostTaskAuthorizer struct {
	checker *permissionChecker
}

// AuthorizeTaskRead 实现 adminapi.TaskAuthorizer。
func (a hostTaskAuthorizer) AuthorizeTaskRead(ctx context.Context,
	caller account.Caller, job task.Job) error {
	actor := caller.Actor()
	trusted, err := a.checker.roots.trustedActor(ctx, actor)
	if err != nil {
		return err
	}
	if trusted {
		return nil
	}
	key := taskReadPermissionKey(job.Kind)
	if key == "" {
		return fmt.Errorf("未知任务类型 %q 的读取权限：拒绝", job.Kind)
	}
	return a.checker.check(ctx, actor.ID, key, "system")
}

// taskReadPermissionKey 把任务类型映射到读取权限键；未知类型 fail-closed。
func taskReadPermissionKey(kind string) string {
	switch {
	case strings.HasPrefix(kind, "report."):
		return "reports.read"
	case strings.HasPrefix(kind, "backup."):
		return "backups.read"
	case strings.HasPrefix(kind, "audit."):
		return "audit.read"
	case strings.HasPrefix(kind, "user.batch."):
		return "users.read"
	case strings.HasPrefix(kind, "mail."), strings.HasPrefix(kind, "webhook."):
		// 通知投递任务只允许受信系统主体读取（无独立管理权限键）。
		return ""
	default:
		return ""
	}
}
