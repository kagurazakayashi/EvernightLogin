package transport

import (
	"fmt"
	"sort"
)

// 本文件登记「账户 / 资料 / 会话 / 注册登录 / MFA / 三种恢复流程」页面与表单
// 操作的 OpenAPI 契约，并提供按命名路由查询的入口。
//
// 契约表与真实路由的分工：
//   - 真实方法/路径来自页面处理器注册的 PageRoute（运行期由 ui.WebUI.Routes()
//     注入，离线由 scripts/reference 用 AST 扫描 ui/ 得到）；
//   - 本表只钉住命名路由对应的请求字段、响应集合、状态转移与限流说明；
//   - Method/Path 同时是契约的一部分：页面路由改动而不同步本表时，构造与
//     scripts/reference -check 都会失败，防止文档与真实注册漂移。
//
// 三种恢复流程在页面层分别是：
//  1. 邮件找回密码（auth.password_forgot / auth.password_reset）；
//  2. 恢复代码 + 重绑安全因素（auth.recovery_code / auth.recovery_rebind / cancel）；
//  3. 客服人工恢复申请/审批/执行（support.recovery_*），与自助流程共享核心但不共用入口。

// pageOperationRegistry 是全部已登记契约（按命名路由索引）。
var pageOperationRegistry = map[string]PageOperation{}

// pageContractGroups 是按领域维护的契约表；init 合并并检查重复，重复属于编程错误。
var pageContractGroups = map[string]map[string]PageOperation{
	"auth":        pageAuthOperations,
	"mfa":         pageMFAOperations,
	"account":     pageAccountOperations,
	"security":    pageSecurityOperations,
	"support":     pageSupportOperations,
	"activity-qr": pageActivityQROperations,
}

// init 合并各领域契约表。
func init() {
	for domain, group := range pageContractGroups {
		for name, operation := range group {
			if _, exists := pageOperationRegistry[name]; exists {
				panic(fmt.Sprintf("transport: 页面操作契约重复登记：%s（%s）", name, domain))
			}
			pageOperationRegistry[name] = operation
		}
	}
}

// pageOperationContract 返回命名路由的操作契约。
func pageOperationContract(name string) (PageOperation, bool) {
	operation, ok := pageOperationRegistry[name]
	return operation, ok
}

// PageOperationContract 返回指定命名路由的页面操作契约，供 scripts/reference
// 离线核对 AST 扫描到的页面路由与契约是否一致。
func PageOperationContract(name string) (PageOperation, bool) {
	return pageOperationContract(name)
}

// PageOperations 返回全部已登记页面操作契约（按命名路由排序的副本）。
func PageOperations() []NamedPageOperation {
	names := make([]string, 0, len(pageOperationRegistry))
	for name := range pageOperationRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	operations := make([]NamedPageOperation, 0, len(names))
	for _, name := range names {
		operations = append(operations, NamedPageOperation{
			Name: name, PageOperation: pageOperationRegistry[name],
		})
	}
	return operations
}

// ===== 字段契约辅助构造器（减少重复，保证写秘密一律 writeOnly） =====

// pageText 构造普通文本字段。
func pageText(name string, required bool, maxLength int, description string) PageField {
	return PageField{Name: name, Kind: PageFieldString, Required: required,
		MaxLength: maxLength, Description: description}
}

// pageSecret 构造只写秘密字段（密码/令牌/恢复码等）。服务端不回声，示例为合成值。
func pageSecret(name string, required bool, maxLength int, description string) PageField {
	return PageField{Name: name, Kind: PageFieldString, Required: required,
		WriteOnly: true, MaxLength: maxLength, Description: description}
}

// pageEnum 构造固定取值字段（确认框等）。
func pageEnum(name string, required bool, values []string, description string) PageField {
	return PageField{Name: name, Kind: PageFieldString, Required: required,
		Enum: values, Description: description}
}

// pageInteger 构造十进制整数字段。
func pageInteger(name string, required bool, description string) PageField {
	return PageField{Name: name, Kind: PageFieldInteger, Required: required,
		Description: description}
}

// pageBoolean 构造布尔语义字段。
func pageBoolean(name string, required bool, description string) PageField {
	return PageField{Name: name, Kind: PageFieldBoolean, Required: required,
		Description: description}
}

// pageFileField 构造 multipart 文件字段。
func pageFileField(name string, required bool, description string) PageField {
	return PageField{Name: name, Kind: PageFieldFile, Required: required, Description: description}
}

// pageQuery 构造 GET 查询参数（除位置外与表单字段相同）。
func pageQuery(field PageField) PageField {
	return field
}

// pageConfirmYes 是“确认继续”的固定值集合（表单按钮提交 yes）。
var pageConfirmYes = []string{"yes"}

// pageConfirmTrue 是布尔确认框的固定值集合（checkbox 提交 true）。
var pageConfirmTrue = []string{"true"}

// pageRowVersion 是乐观并发版本字段的通用契约：缺失或过期返回 409，要求重新读取。
func pageRowVersion() PageField {
	return pageInteger("row_version",
		true, "乐观并发版本：取自当前页面渲染的行版本，缺失/非数字/已过期返回 409，要求重新读取后再提交。")
}
