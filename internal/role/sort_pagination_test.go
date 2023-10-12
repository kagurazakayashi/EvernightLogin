package role_test

// 步骤 216：角色列表与角色分配列表的白名单排序、稳定同值次序、数据源分页、
// 非法输入拒绝。offset 只保证当前排序下顺序稳定，不提供并发快照。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/role"
)

func TestRoleListSortWhitelistAndPagination(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createRole(role.ScopeSystem, "sort-alpha", "Alpha角色")
	env.createRole(role.ScopeSystem, "sort-zeta", "Zeta角色")
	env.createRole(role.ScopeSystem, "sort-middle", "Middle角色")

	page, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 10, Sort: role.SortName})
	if err != nil {
		t.Fatalf("按名称排序失败: %v", err)
	}
	names := make([]string, 0, len(page.Roles))
	for _, record := range page.Roles {
		names = append(names, record.Name)
	}
	if len(names) < 3 || names[0] != "Alpha角色" || names[len(names)-1] != "Zeta角色" {
		t.Fatalf("名称升序 = %v", names)
	}

	// 分页拼接与整页顺序一致，末页 HasMore=false。
	fullIDs := make([]string, 0, len(names))
	for offset := 0; offset < len(names); offset++ {
		current, pageErr := env.service.ListRoles(ctx, env.system, role.ListRequest{
			Limit: 1, Offset: offset, Sort: role.SortName})
		if pageErr != nil {
			t.Fatalf("分页 offset=%d 失败: %v", offset, pageErr)
		}
		if len(current.Roles) != 1 {
			t.Fatalf("offset=%d 条数 = %d", offset, len(current.Roles))
		}
		wantMore := offset < len(names)-1
		if current.HasMore != wantMore {
			t.Fatalf("offset=%d HasMore = %v，期望 %v", offset, current.HasMore, wantMore)
		}
		fullIDs = append(fullIDs, current.Roles[0].ID)
	}
	for index, record := range page.Roles {
		if fullIDs[index] != record.ID {
			t.Fatalf("分页拼接与整页顺序不一致: %d %s != %s", index, fullIDs[index], record.ID)
		}
	}

	// 降序方向。
	desc, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 10, Sort: role.SortName, Descending: true})
	if err != nil || len(desc.Roles) < 3 || desc.Roles[0].Name != "Zeta角色" {
		t.Fatalf("降序结果 = %+v, %v", desc.Roles, err)
	}

	if _, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 10, Sort: role.SortField("bogus")}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("非法排序字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 101}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("limit 越界错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListRoles(ctx, env.system, role.ListRequest{
		Limit: 10, Offset: -1}); !errors.Is(err, role.ErrInvalidRequest) {
		t.Fatalf("负 offset 错误 = %v，期望 ErrInvalidRequest", err)
	}
}

func TestRoleAssignmentsPagedInDataSource(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	operatorRole := env.createRole(role.ScopeSystem, "assign-paged", "分配分页角色")
	for _, userID := range []string{testUserActive, testUserOther} {
		if _, err := env.service.AssignUserRole(ctx, env.system, operatorRole.ID, userID); err != nil {
			t.Fatalf("分配用户 %s 失败: %v", userID, err)
		}
	}

	// 用户分配按稳定 ID 排序后逐页读取；每页 1 条，验证 HasMore 与拼接。
	seen := make([]string, 0, 2)
	for offset := 0; offset < 2; offset++ {
		result, err := env.service.ListRoleAssignmentsPaged(ctx, env.system,
			role.AssignmentListRequest{RoleID: operatorRole.ID, UserLimit: 1,
				UserOffset: offset, GroupLimit: 1, GroupOffset: offset,
				Sort: role.AssignmentSortTargetID})
		if err != nil {
			t.Fatalf("offset=%d 读取分配失败: %v", offset, err)
		}
		if len(result.Users) != 1 {
			t.Fatalf("offset=%d 用户分配数 = %d", offset, len(result.Users))
		}
		if result.UsersHasMore != (offset == 0) {
			t.Fatalf("offset=%d UsersHasMore = %v", offset, result.UsersHasMore)
		}
		seen = append(seen, result.Users[0].UserID)
	}
	if seen[0] == seen[1] {
		t.Fatalf("分配分页重复返回同一用户: %v", seen)
	}

	// 非法分页/排序 fail-closed。
	if _, err := env.service.ListRoleAssignmentsPaged(ctx, env.system,
		role.AssignmentListRequest{RoleID: operatorRole.ID, UserLimit: 101}); !errors.Is(err,
		role.ErrInvalidRequest) {
		t.Fatalf("非法 limit 错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListRoleAssignmentsPaged(ctx, env.system,
		role.AssignmentListRequest{RoleID: operatorRole.ID, UserLimit: 10,
			Sort: role.AssignmentSortField("bogus")}); !errors.Is(err,
		role.ErrInvalidRequest) {
		t.Fatalf("非法分配排序错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 角色不存在（已通过格式检查的动作目标）返回 ErrRoleNotFound 语义。
	if _, err := env.service.ListRoleAssignmentsPaged(ctx, env.system,
		role.AssignmentListRequest{RoleID: "role_00000000000000000000000000000000",
			UserLimit: 10}); !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("不存在角色错误 = %v，期望 ErrRoleNotFound", err)
	}
}
