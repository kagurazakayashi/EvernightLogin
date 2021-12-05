package adminapi

import (
	"github.com/kagurazakayashi/EvernightLogin/internal/auditops"
	"github.com/kagurazakayashi/EvernightLogin/internal/backupadmin"
	"github.com/kagurazakayashi/EvernightLogin/internal/reports"
	"github.com/kagurazakayashi/EvernightLogin/internal/session"
	"github.com/kagurazakayashi/EvernightLogin/internal/task"
)

// 编译期断言：生产领域服务必须满足管理 API 的最小契约。任何签名变化都会在
// 编译期失败，而不是等到运行时装配才暴露。
var (
	_ ManagementSession = (*session.Service)(nil)
	_ AuditService      = (*auditops.Service)(nil)
	_ ReportService     = (*reports.Service)(nil)
	_ ReportPlanService = (*reports.PlanService)(nil)
	_ BackupService     = (*backupadmin.Service)(nil)
	_ TaskReader        = (*task.Executor)(nil)
)
