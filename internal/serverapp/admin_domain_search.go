package serverapp

// 步骤 262：管理 HTTP 领域列表（角色/权限/用户组/应用）的有界搜索参数解析。
//
// 与 261 的用户/成员搜索约定一致：复用 internal/search 的输入规范化（NFKC +
// Unicode 大小写折叠 + 64 字符上限 + 控制字符拒绝）与 LIKE 转义；本 helper 只负责
// 解析 search 文本与逗号分隔的 search_fields，具体字段白名单由各领域服务在授权与
// 范围过滤之后校验（未知字段返回 REQ_INVALID）。
//
// search_fields 为空表示使用该领域默认字段；本 helper 不猜测领域默认值，直接把
// 空切片交给领域层，保持各领域自己的默认语义（角色/组/权限=name+key，应用=name+
// description）。

import (
	"net/http"
	"strings"

	"github.com/kagurazakayashi/EvernightLogin/internal/adminapi"
	"github.com/kagurazakayashi/EvernightLogin/internal/app"
	"github.com/kagurazakayashi/EvernightLogin/internal/group"
	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
	"github.com/kagurazakayashi/EvernightLogin/internal/role"
	"github.com/kagurazakayashi/EvernightLogin/internal/search"
)

// parseAdminDomainSearch 解析领域列表的可选搜索参数。搜索文本超长/含控制字符返回
// REQ_INVALID 领域错误；search_fields 只做逗号拆分与去空，未知字段由领域层拒绝。
func parseAdminDomainSearch(request *http.Request) (string, []string, error) {
	searchText, err := search.NormalizeQuery(strings.TrimSpace(request.URL.Query().Get("search")))
	if err != nil {
		return "", nil, &adminapi.DomainError{Code: "REQ_INVALID",
			Message: "搜索条件无效：仅支持 64 个字符以内的字面搜索", Cause: err}
	}
	rawFields := strings.TrimSpace(request.URL.Query().Get("search_fields"))
	if rawFields == "" {
		return searchText, nil, nil
	}
	fields := make([]string, 0, 2)
	for _, part := range strings.Split(rawFields, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		fields = append(fields, value)
	}
	return searchText, fields, nil
}

// toRoleSearchFields 把 HTTP 字符串字段转换为角色领域白名单类型；未知值由领域
// 服务在授权后校验并返回 REQ_INVALID（不在传输层猜测语义）。
func toRoleSearchFields(fields []string) []role.RoleSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]role.RoleSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, role.RoleSearchField(field))
	}
	return converted
}

// toGroupSearchFields 同上，用于用户组领域。
func toGroupSearchFields(fields []string) []group.GroupSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]group.GroupSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, group.GroupSearchField(field))
	}
	return converted
}

// toPermissionSearchFields 同上，用于权限目录领域。
func toPermissionSearchFields(fields []string) []permission.PermissionSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]permission.PermissionSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, permission.PermissionSearchField(field))
	}
	return converted
}

// toApplicationSearchFields 同上，用于应用领域。
func toApplicationSearchFields(fields []string) []app.ApplicationSearchField {
	if len(fields) == 0 {
		return nil
	}
	converted := make([]app.ApplicationSearchField, 0, len(fields))
	for _, field := range fields {
		converted = append(converted, app.ApplicationSearchField(field))
	}
	return converted
}
