package transport

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// 本文件登记管理 JSON API（默认挂载于 server.path_prefix + /admin/v1）中
// **运维、报告、客服**域的机器可读契约，供离线 OpenAPI 生成与校验使用。
//
// 范围与边界：
//   - 覆盖审计、报告与报告计划、任务、备份恢复、配置诊断、通知、客服工单与人工恢复；
//   - 用户/角色/应用/会话等管理组属步骤 269，不在本表（生成器按域前缀排除并校验）；
//   - 直接改名/改密 HTTP 端点属 258/259，本表不写占位 schema；
//   - 邮件投递记录端点属后续步骤（266 在途），本表不登记、生成器断言不存在占位。
//
// 与步骤 268 页面契约的关系：两者同属 HTTP 契约层，但传输语义不同——
// 管理 API 是 JSON API：成功 `{"ok":true,"request_id":"…","data":…}`，
// 失败 `{"ok":false,"code":"…","message":"…","request_id":"…"}`，错误码来自
// 根包错误注册表；页面契约则是 HTML 语义（见 pagecontracts*.go）。
//
// 方法与路径由 adminapi/internal/serverapp 真实注册的 DomainRoute 提供（离线由
// AST 扫描生成 docs/reference/http-routes.json）；本表按 "METHOD pattern" 钉住
// 请求/响应语义，两者不一致时 scripts/adminapi-doc -check 失败（非零退出）。
// 管理 API 的路由是**按装配条件注册**的：未装配的领域服务返回 404，本表描述的是
// “服务装配后可达的契约”，不表示每个部署都启用全部领域。

// AdminAPIBasePath 是管理 JSON API 的默认站内前缀（部署时可用配置覆盖；
// 实际完整路径 = server.path_prefix + 该前缀）。
const AdminAPIBasePath = "/admin/v1"

// adminAPIEnvelopeDescription 是管理 API 统一响应信封说明。
const adminAPIEnvelopeDescription = "管理 API 统一 JSON 信封：成功 {\"ok\":true,\"request_id\":\"…\",\"data\":…}；" +
	"失败 {\"ok\":false,\"code\":\"…\",\"message\":\"…\",\"request_id\":\"…\"}；" +
	"错误码来自根包 errs 注册表（HTTP 状态与默认消息同源）；请求编号优先复用上游 X-Request-ID，否则内部生成。"

// AdminAPIEnvelopeDescription 返回管理 API 统一响应信封说明，供文档生成器复用。
func AdminAPIEnvelopeDescription() string { return adminAPIEnvelopeDescription }

// AdminParam 是管理 API 的路径参数或查询参数契约。
type AdminParam struct {
	// Name 是参数名（路径参数与模式中的 {name} 一致）。
	Name string
	// Type 是 OpenAPI 类型：string/integer/boolean。
	Type string
	// Description 是直白中文说明（含来源、范围与默认值）。
	Description string
	// Required 表示必填。
	Required bool
	// Enum 是固定取值集合；空表示自由输入。
	Enum []string
	// Min/Max 是整数的允许范围；0 表示不单独标注。
	Min int
	Max int
	// Default 是默认值说明；空表示无默认值。
	Default string
}

// AdminField 是管理 API JSON 请求体字段契约。
type AdminField struct {
	// Name 是 JSON 字段名（严格解码：未知字段拒绝）。
	Name string
	// Type 是 OpenAPI 类型。
	Type string
	// Description 是直白中文说明。
	Description string
	// Required 表示必填。
	Required bool
	// Enum 是固定取值集合。
	Enum []string
	// Secret 表示只写敏感输入（密码/TOTP/下载令牌），示例使用合成值。
	Secret bool
	// MaxLength 是字符串长度上限；0 表示不单独标注。
	MaxLength int
}

// AdminOperation 是一条管理 API 操作的完整契约。
type AdminOperation struct {
	// Method/Pattern 与真实注册路由钉住（pattern 相对管理前缀）。
	Method  string
	Pattern string
	// Domain 是文档分组标签：audit/reports/plans/backups/tasks/diagnostics/settings/notifications/support/core。
	Domain string
	// Summary 是一句话摘要；Description 是构造请求与理解结果的完整说明。
	Summary     string
	Description string
	// Permissions 是调用所需权限键（任一满足；root 按 252 内核语义拥有全部已实现权限）。
	Permissions []string
	// SessionBaseline 表示只要求管理会话基线（强认证会话），不需要额外权限键。
	SessionBaseline bool
	// RootOnly 表示仅 root（受信本地主体）可调用。
	RootOnly bool
	// Sensitive 表示敏感操作：由 internal/policy 复核再次认证/强认证新鲜度与策略下限。
	Sensitive bool
	// Confirm 表示请求体必须 confirm=true（确认不是授权）。
	Confirm bool
	// Reason 表示请求体必须提供非空 reason（进入真实审计）。
	Reason bool
	// Async 表示“已提交/受理≠完成”：响应返回真实任务/状态，需按任务编号查询终态。
	Async bool
	// Cancelable 表示支持取消；取消响应只表示“已受理取消”，终态以任务/状态为准。
	Cancelable bool
	// Download 描述下载语义：""（无）、"stream"（直接流式下载）、
	// "ticket-issue"（签发一次性下载票据）、"ticket-redeem"（消费票据流式下载）。
	Download string
	// Path 是路径参数；Query 是查询参数；Body 是 JSON 请求体字段。
	Path  []AdminParam
	Query []AdminParam
	Body  []AdminField
	// Success 是成功 data 的 schema 引用：组件名（见 adminComponentSchemas）、
	// "object"（通用对象）或 "list:<key>:<itemComponent>"（分页列表）。
	Success string
	// ExtraKeys 是列表成功响应 data 中除 <key>/has_more/limit/offset 外的额外键说明。
	ExtraKeys []string
	// Notes 是操作特有边界（下载票据期限/单次、取消语义、字段裁剪等）。
	Notes []string
}

// NamedAdminOperation 是带 "METHOD pattern" 键名的契约。
type NamedAdminOperation struct {
	Key     string
	Method  string
	Pattern string
	AdminOperation
}

// AdminDomainOrder 是文档与校验使用的稳定域顺序。
var AdminDomainOrder = []string{
	"core", "audit", "reports", "plans", "backups", "tasks", "diagnostics",
	"settings", "notifications", "deliveries", "support",
}

// AdminDomainTitles 是域的中文标题。
var AdminDomainTitles = map[string]string{
	"core":          "基础（元信息/错误码）",
	"audit":         "审计（事件/保留策略/导出/清理）",
	"reports":       "报告（历史/快照/下载票据/清理）",
	"plans":         "报告计划与备份计划",
	"backups":       "备份（产物/任务/下载票据/保留/清理）",
	"tasks":         "任务（详情/尝试历史）",
	"diagnostics":   "配置诊断（脱敏运行诊断）",
	"settings":      "配置管理（脱敏字段/校验/更新/恢复）",
	"notifications": "安全通知与本地捕获测试",
	"deliveries":    "邮件投递记录（脱敏只读）",
	"support":       "客服工单与人工恢复",
}

// adminOperationGroups 是各域契约表（各域文件在自己的 init 中注册；合并为懒加载，
// 避免依赖包内 init 执行顺序）。
var adminOperationGroups = map[string]map[string]AdminOperation{}

// adminOperationRegistry 是全部管理 API 契约（"METHOD pattern" 索引），首次使用时
// 由各域表合并构建。
var adminOperationRegistry map[string]AdminOperation

// adminRegistryOnce 保证合并只执行一次。
var adminRegistryOnce sync.Once

// buildAdminOperationRegistry 合并各域契约表并检查重复/域一致性；重复属于编程错误，
// 用 panic 在开发/测试期立即暴露。
func buildAdminOperationRegistry() {
	registry := make(map[string]AdminOperation, 128)
	for domain, group := range adminOperationGroups {
		for key, operation := range group {
			if _, exists := registry[key]; exists {
				panic(fmt.Sprintf("transport: 管理 API 契约重复登记：%s（%s）", key, domain))
			}
			if operation.Domain != domain {
				panic(fmt.Sprintf("transport: 管理 API 契约 %s 的域名 %q 与分组 %q 不一致",
					key, operation.Domain, domain))
			}
			registry[key] = operation
		}
	}
	adminOperationRegistry = registry
}

// adminOperation 返回合并后的契约表（懒加载）。
func adminOperation() map[string]AdminOperation {
	adminRegistryOnce.Do(buildAdminOperationRegistry)
	return adminOperationRegistry
}

// adminOperationKey 生成 "METHOD pattern" 键。
func adminOperationKey(method, pattern string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(pattern)
}

// AdminOperations 返回全部管理 API 契约（按域顺序、再按路径排序）。
func AdminOperations() []NamedAdminOperation {
	registry := adminOperation()
	operations := make([]NamedAdminOperation, 0, len(registry))
	for key, operation := range registry {
		operations = append(operations, NamedAdminOperation{
			Key: key, Method: operation.Method, Pattern: operation.Pattern,
			AdminOperation: operation,
		})
	}
	domainRank := make(map[string]int, len(AdminDomainOrder))
	for index, domain := range AdminDomainOrder {
		domainRank[domain] = index
	}
	sort.Slice(operations, func(left, right int) bool {
		leftRank, rightRank := domainRank[operations[left].Domain], domainRank[operations[right].Domain]
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if operations[left].Pattern != operations[right].Pattern {
			return operations[left].Pattern < operations[right].Pattern
		}
		return operations[left].Method < operations[right].Method
	})
	return operations
}

// AdminOperationContract 返回指定方法/路径模式的管理 API 契约。
func AdminOperationContract(method, pattern string) (AdminOperation, bool) {
	operation, ok := adminOperation()[adminOperationKey(method, pattern)]
	return operation, ok
}

// ===== 契约辅助构造器 =====

// adminParam 构造路径参数。
func adminParam(name, description string) AdminParam {
	return AdminParam{Name: name, Type: "string", Description: description, Required: true}
}

// adminQuery 构造可选查询字符串参数。
func adminQuery(name, description string) AdminParam {
	return AdminParam{Name: name, Type: "string", Description: description}
}

// adminQueryInt 构造可选整数查询参数（min/max 标注允许范围）。
func adminQueryInt(name string, minValue, maxValue int, description string) AdminParam {
	return AdminParam{Name: name, Type: "integer", Description: description,
		Min: minValue, Max: maxValue}
}

// adminQueryEnum 构造枚举查询参数。
func adminQueryEnum(name string, values []string, description string) AdminParam {
	return AdminParam{Name: name, Type: "string", Description: description, Enum: values}
}

// adminQueryBool 构造布尔查询参数（仅 true/false/1/0）。
func adminQueryBool(name, description string) AdminParam {
	return AdminParam{Name: name, Type: "boolean", Description: description}
}

// adminBody 构造必填 JSON 字段。
func adminBody(name, fieldType, description string) AdminField {
	return AdminField{Name: name, Type: fieldType, Description: description, Required: true}
}

// adminBodyOptional 构造可选 JSON 字段。
func adminBodyOptional(name, fieldType, description string) AdminField {
	return AdminField{Name: name, Type: fieldType, Description: description}
}

// adminBodySecret 构造只写敏感字段（示例使用合成值）。
func adminBodySecret(name, description string, maxLength int) AdminField {
	return AdminField{Name: name, Type: "string", Description: description,
		Required: true, Secret: true, MaxLength: maxLength}
}

// adminConfirmField 是写操作的确认字段（确认不是授权）。
func adminConfirmField() AdminField {
	return AdminField{Name: "confirm", Type: "boolean", Required: true,
		Description: "必须为 true 显式确认目标与后果；确认不是授权，权限/敏感策略/审计仍由服务端重新判定。"}
}

// adminReasonField 是取消/清理/保留策略等写操作的原因字段（进入真实审计）。
func adminReasonField() AdminField {
	return AdminField{Name: "reason", Type: "string", Required: true, MaxLength: 256,
		Description: "操作原因；进入真实审计，不能为空，最多 256 字节。"}
}

// adminRequestIDField 是可选请求编号字段（用于幂等/关联）。
func adminRequestIDField() AdminField {
	return AdminField{Name: "request_id", Type: "string", MaxLength: 64,
		Description: "可选请求编号：优先复用并进入审计，仅用于关联排障与幂等，不参与授权。"}
}

// adminPaginationQuery 是管理列表通用分页参数（limit/offset）。
func adminPaginationQuery() []AdminParam {
	return []AdminParam{
		adminQueryInt("limit", 1, 100, "每页条数，默认 20，最大 100；显式非法值返回 400，不静默截断。"),
		adminQueryInt("offset", 0, 1_000_000, "偏移分页，默认 0，最大 1000000；与游标分页互斥。"),
	}
}

// adminSearchQuery 是管理列表通用有界字面搜索参数（步骤 261/262/263 约定）。
func adminSearchQuery(fieldsDescription string) []AdminParam {
	return []AdminParam{
		adminQuery("search", "有界字面搜索（NFKC + 大小写折叠，最多 64 字符）；空表示不过滤。"),
		adminQuery("search_fields", "逗号分隔的搜索字段白名单："+fieldsDescription+"；未知字段返回 400。"),
	}
}

// adminPageType 断言方法是否为写操作。
func adminWritesBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// ValidateAdminOperation 校验单条契约自身完整性（供测试与生成器共用）。
func ValidateAdminOperation(operation AdminOperation) error {
	if strings.TrimSpace(operation.Method) == "" || strings.TrimSpace(operation.Pattern) == "" {
		return fmt.Errorf("缺少方法或路径模式")
	}
	switch strings.ToUpper(operation.Method) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		return fmt.Errorf("%s %s 的 HTTP 方法未登记", operation.Method, operation.Pattern)
	}
	if !validAdminPathPattern(operation.Pattern) {
		return fmt.Errorf("%s 的路径模式非法", operation.Pattern)
	}
	if strings.TrimSpace(operation.Summary) == "" || strings.TrimSpace(operation.Description) == "" {
		return fmt.Errorf("%s %s 缺少摘要或说明", operation.Method, operation.Pattern)
	}
	if operation.Domain == "" || AdminDomainTitles[operation.Domain] == "" {
		return fmt.Errorf("%s %s 的域 %q 未登记", operation.Method, operation.Pattern, operation.Domain)
	}
	if operation.RootOnly && len(operation.Permissions) > 0 {
		return fmt.Errorf("%s %s 同时声明 root-only 与普通权限，语义冲突", operation.Method, operation.Pattern)
	}
	if !operation.RootOnly && len(operation.Permissions) == 0 && !operation.SessionBaseline {
		return fmt.Errorf("%s %s 未声明权限、root-only 或管理会话基线", operation.Method, operation.Pattern)
	}
	if operation.Confirm && !adminWritesBody(operation.Method) {
		return fmt.Errorf("%s %s 是读操作却要求 confirm", operation.Method, operation.Pattern)
	}
	if operation.Reason && !operation.Confirm {
		return fmt.Errorf("%s %s 要求原因但未要求确认", operation.Method, operation.Pattern)
	}
	if adminWritesBody(operation.Method) && len(operation.Body) == 0 && operation.Download != "ticket-redeem" &&
		operation.Method != http.MethodDelete {
		return fmt.Errorf("%s %s 是写操作但未声明请求体字段", operation.Method, operation.Pattern)
	}
	// 路径参数必须与模式占位符一一对应。
	placeholders := adminPathPlaceholders(operation.Pattern)
	declared := map[string]bool{}
	for _, param := range operation.Path {
		declared[param.Name] = true
	}
	if len(placeholders) != len(declared) {
		return fmt.Errorf("%s 的路径参数声明与占位符数量不一致", operation.Pattern)
	}
	for _, placeholder := range placeholders {
		if !declared[placeholder] {
			return fmt.Errorf("%s 缺少路径参数 %s 的声明", operation.Pattern, placeholder)
		}
	}
	// 字段名唯一、类型合法、秘密字段必须带长度上限说明。
	names := map[string]bool{}
	for _, field := range operation.Body {
		if strings.TrimSpace(field.Name) == "" {
			return fmt.Errorf("%s %s 存在空字段名", operation.Method, operation.Pattern)
		}
		if names[field.Name] {
			return fmt.Errorf("%s %s 字段 %s 重复", operation.Method, operation.Pattern, field.Name)
		}
		names[field.Name] = true
		switch field.Type {
		case "string", "integer", "boolean", "object", "array":
		default:
			return fmt.Errorf("%s %s 字段 %s 的类型 %q 未登记",
				operation.Method, operation.Pattern, field.Name, field.Type)
		}
		if field.Secret && field.MaxLength == 0 {
			return fmt.Errorf("%s %s 秘密字段 %s 缺少长度上限",
				operation.Method, operation.Pattern, field.Name)
		}
	}
	for _, param := range append(append([]AdminParam(nil), operation.Path...), operation.Query...) {
		if strings.TrimSpace(param.Name) == "" || param.Type == "" {
			return fmt.Errorf("%s %s 存在不完整的参数声明", operation.Method, operation.Pattern)
		}
	}
	if strings.TrimSpace(operation.Success) == "" {
		return fmt.Errorf("%s %s 未声明成功响应 data", operation.Method, operation.Pattern)
	}
	return nil
}

// validAdminPathPattern 校验相对管理前缀的路径模式：段用 / 连接，参数段为 {name}。
func validAdminPathPattern(pattern string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "/") || strings.HasSuffix(pattern, "/") {
		return false
	}
	if strings.ContainsAny(pattern, " ?#\\%") {
		return false
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" {
			return false
		}
		if strings.HasPrefix(segment, "{") || strings.HasSuffix(segment, "}") {
			if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") ||
				len(segment) < 3 {
				return false
			}
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			if strings.ContainsAny(name, "}{/ ") {
				return false
			}
		}
	}
	return true
}

// adminPathPlaceholders 返回路径模式中的参数名列表（按出现顺序）。
func adminPathPlaceholders(pattern string) []string {
	var placeholders []string
	for _, segment := range strings.Split(pattern, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			placeholders = append(placeholders, strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}"))
		}
	}
	return placeholders
}

// AdminScopeExclusions 返回本步明确**不登记**的管理 API 域与原因（生成器断言不出现
// 对应前缀的契约，防止把未实现/未开始的端点写成占位 schema）。
func AdminScopeExclusions() map[string]string {
	return map[string]string{
		"users":        "管理组（用户）OpenAPI 属步骤 269，不重复造",
		"applications": "管理组（应用）OpenAPI 属步骤 269，不重复造",
		"roles":        "管理组（角色）OpenAPI 属步骤 269，不重复造",
		"groups":       "管理组（用户组）OpenAPI 属步骤 269，不重复造",
		"permissions":  "管理组（权限）OpenAPI 属步骤 269，不重复造",
		"sessions":     "管理组（会话）OpenAPI 属步骤 269，不重复造",
	}
}
