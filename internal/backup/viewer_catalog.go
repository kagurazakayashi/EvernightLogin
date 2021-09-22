package backup

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 受限查询目录（步骤 83）。离线查看/导出从不执行任意 SQL：
//
//  1. 表名只允许本文件静态白名单中的已知表；未知表一律拒绝。
//  2. 字段名在运行时来自认证解密后的快照自身 schema（PRAGMA table_info），
//     并且只接受符合安全标识符规则的列；用户输入的字段名只用于在白名单集合中
//     查找，绝不直接拼接进 SQL（SQL 中的标识符来自已校验的 schema 名并加双引号）。
//  3. 认证秘密/会话摘要等敏感字段由显式清单 + 通用命名规则识别，默认排除；
//     只有显式 --include-sensitive 才可读取/导出，且导出落地后需收紧文件权限。
//
// 白名单刻意只覆盖查看/排障常用的只读表：认证凭证、一次性令牌、WebAuthn 凭据、
// 恢复代码、Webhook 端点秘密等表不在此目录，不能通过本工具读取。
type PreviewTable struct {
	// Name 是 SQLite 表名（静态白名单键）。
	Name string `json:"name"`
	// Category 是稳定类别标识，供按类别选择。
	Category string `json:"category"`
	// Description 是直白中文说明。
	Description string `json:"description"`
}

// 稳定类别标识。
const (
	PreviewCategoryMeta    = "meta"
	PreviewCategoryAccount = "account"
	PreviewCategoryAccess  = "access"
	PreviewCategorySession = "session"
	PreviewCategoryOAuth   = "oauth"
	PreviewCategoryAudit   = "audit"
	PreviewCategoryOps     = "ops"
)

// previewTableCatalog 是受限查询允许的表白名单。顺序即 CLI 展示顺序。
var previewTableCatalog = []PreviewTable{
	{Name: "schema_history", Category: PreviewCategoryMeta,
		Description: "已应用的数据库迁移记录（版本、说明、应用时间）"},
	{Name: "restore_generation", Category: PreviewCategoryMeta,
		Description: "恢复代际与恢复状态锚点（用于使旧凭证在恢复后失效）"},
	{Name: "users", Category: PreviewCategoryAccount,
		Description: "账户资料与状态（密码哈希/令牌/恢复码不在本表，也不在此目录）"},
	{Name: "user_emails", Category: PreviewCategoryAccount,
		Description: "账户邮箱与验证时间（属于个人信息，导出前确认用途）"},
	{Name: "avatars", Category: PreviewCategoryAccount,
		Description: "头像元数据（图片正文以附件条目逐项提取，不在此表）"},
	{Name: "applications", Category: PreviewCategoryAccess,
		Description: "应用登记资料与状态"},
	{Name: "app_memberships", Category: PreviewCategoryAccess,
		Description: "应用成员关系与应用内资料"},
	{Name: "scopes", Category: PreviewCategoryAccess,
		Description: "作用范围（系统或应用）"},
	{Name: "roles", Category: PreviewCategoryAccess,
		Description: "角色定义与作用范围"},
	{Name: "permissions", Category: PreviewCategoryAccess,
		Description: "权限定义与作用范围"},
	{Name: "role_permissions", Category: PreviewCategoryAccess,
		Description: "角色与权限的组合关系"},
	{Name: "user_roles", Category: PreviewCategoryAccess,
		Description: "用户角色分配与数据范围"},
	{Name: "user_groups", Category: PreviewCategoryAccess,
		Description: "用户组定义与作用范围"},
	{Name: "group_members", Category: PreviewCategoryAccess,
		Description: "用户组成员关系"},
	{Name: "group_roles", Category: PreviewCategoryAccess,
		Description: "用户组角色分配与数据范围"},
	{Name: "permission_delegations", Category: PreviewCategoryAccess,
		Description: "委派资格（可转授权限范围与目标限制）"},
	{Name: "sessions", Category: PreviewCategorySession,
		Description: "会话元数据与生命周期；会话秘密/CSRF 摘要默认排除"},
	{Name: "oauth_clients", Category: PreviewCategoryOAuth,
		Description: "OAuth 客户端登记元数据；客户端密钥哈希不在本表"},
	{Name: "audit_events", Category: PreviewCategoryAudit,
		Description: "安全审计事件（动作、结果、目标与稳定错误码）"},
	{Name: "stats_business_activity", Category: PreviewCategoryAudit,
		Description: "可信业务活动统计记录"},
	{Name: "backup_artifacts", Category: PreviewCategoryOps,
		Description: "备份产物登记元数据（文件名、大小、摘要、校验/清理状态）"},
	{Name: "backup_jobs", Category: PreviewCategoryOps,
		Description: "备份任务索引（不包含任务载荷与密钥）"},
	{Name: "restore_runs", Category: PreviewCategoryOps,
		Description: "恢复运行记录（状态、操作者、结果摘要）"},
	{Name: "report_history", Category: PreviewCategoryOps,
		Description: "历史报告记录（状态、格式、产物引用与错误码）"},
	{Name: "report_plans", Category: PreviewCategoryOps,
		Description: "定期报告计划（周期、范围与启用状态）"},
}

// previewTableIndex 是表名到目录项的索引（只读，不导出）。
var previewTableIndex = func() map[string]PreviewTable {
	index := make(map[string]PreviewTable, len(previewTableCatalog))
	for _, table := range previewTableCatalog {
		index[table.Name] = table
	}
	return index
}()

// explicitSensitiveColumns 是各表明确列出的敏感列及原因。即使列名不匹配通用
// 规则，也必须默认排除。当前白名单表的敏感列主要是会话凭据摘要。
var explicitSensitiveColumns = map[string]map[string]string{
	"sessions": {
		"secret_digest": "会话秘密摘要（持有可冒充会话，默认排除）",
		"csrf_digest":   "CSRF 令牌摘要（默认排除）",
	},
	"oauth_clients": {
		"client_secret_hash": "OAuth 客户端密钥哈希（默认排除）",
	},
}

// sensitiveColumnPattern 是通用敏感列识别规则。列名（小写）命中以下任一模式即
// 视为敏感：认证秘密、令牌、密码、凭据、私钥、摘要、盐、恢复码等。规则默认
// 拒绝：无法判断的外来列若命中敏感词一律不默认导出。
var sensitiveColumnPattern = regexp.MustCompile(
	`(^|_)(secret|secrets|token|tokens|password|passwd|credential|credentials|` +
		`private_key|api_key|salt|recovery_code|hash|digest|csrf)(_|$)`)

// sensitiveColumnReason 报告某表的列是否属于默认排除的高敏字段及原因。
func sensitiveColumnReason(table, column string) (string, bool) {
	if columns, ok := explicitSensitiveColumns[table]; ok {
		if reason, exists := columns[column]; exists {
			return reason, true
		}
	}
	if sensitiveColumnPattern.MatchString(strings.ToLower(column)) {
		return "认证秘密/令牌/摘要类字段（默认排除，显式 --include-sensitive 才可导出）", true
	}
	return "", false
}

// PreviewTables 返回受限查询表目录的副本（调用方不得修改内部状态）。
func PreviewTables() []PreviewTable {
	result := make([]PreviewTable, len(previewTableCatalog))
	copy(result, previewTableCatalog)
	return result
}

// lookupPreviewTable 在静态白名单中查找表；不存在返回 false。
func lookupPreviewTable(name string) (PreviewTable, bool) {
	table, ok := previewTableIndex[name]
	return table, ok
}

// safeSQLIdentifier 报告字段/表名是否符合安全标识符规则。SQL 标识符只允许来自
// 快照 schema 且匹配该规则的名字（再统一加双引号），用户输入永远不会直接成为
// SQL 文本。
var safeSQLIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// quoteSQLiteIdentifier 把已通过安全规则校验的标识符加双引号；未通过时返回
// 错误而不是转义后使用（默认拒绝，避免依赖转义细节）。
func quoteSQLiteIdentifier(name string) (string, error) {
	if !safeSQLIdentifier.MatchString(name) {
		return "", fmt.Errorf("%w: 标识符不合法", ErrQueryInvalid)
	}
	return `"` + name + `"`, nil
}

// tableNamesForDisplay 返回目录表名列表（排序后，供错误信息提示）。
func tableNamesForDisplay() []string {
	names := make([]string, 0, len(previewTableCatalog))
	for _, table := range previewTableCatalog {
		names = append(names, table.Name)
	}
	sort.Strings(names)
	return names
}
