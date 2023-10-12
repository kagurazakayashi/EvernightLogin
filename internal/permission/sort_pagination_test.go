package permission_test

// 步骤 216：权限目录列表的白名单排序、稳定顺序、数据源分页与非法输入拒绝。

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/permission"
)

func TestPermissionListSortWhitelistAndPagination(t *testing.T) {
	env := prepareEnv(t)
	ctx := context.Background()
	env.createSystemPermission("sort.alpha", false, false)
	env.createSystemPermission("sort.zeta", false, false)
	env.createSystemPermission("sort.middle", false, false)

	page, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 10, Sort: permission.SortKey})
	if err != nil {
		t.Fatalf("按机器标识排序失败: %v", err)
	}
	if len(page.Permissions) < 3 {
		t.Fatalf("权限数 = %d", len(page.Permissions))
	}
	keys := make([]string, 0, len(page.Permissions))
	for _, record := range page.Permissions {
		keys = append(keys, record.Key)
	}
	for index := 1; index < len(keys); index++ {
		if keys[index-1] > keys[index] {
			t.Fatalf("机器标识未按升序稳定排列: %v", keys)
		}
	}

	// 分页拼接与整页一致。
	fullIDs := make([]string, 0, len(keys))
	for offset := 0; offset < len(keys); offset++ {
		current, pageErr := env.service.ListPermissions(ctx, env.system,
			permission.ListRequest{Limit: 1, Offset: offset, Sort: permission.SortKey})
		if pageErr != nil {
			t.Fatalf("分页 offset=%d 失败: %v", offset, pageErr)
		}
		if len(current.Permissions) != 1 {
			t.Fatalf("offset=%d 条数 = %d", offset, len(current.Permissions))
		}
		if current.HasMore != (offset < len(keys)-1) {
			t.Fatalf("offset=%d HasMore = %v", offset, current.HasMore)
		}
		fullIDs = append(fullIDs, current.Permissions[0].ID)
	}
	for index, record := range page.Permissions {
		if fullIDs[index] != record.ID {
			t.Fatalf("分页拼接与整页顺序不一致: %d %s != %s", index, fullIDs[index], record.ID)
		}
	}

	if _, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 10, Sort: permission.SortField("bogus")}); !errors.Is(err,
		permission.ErrInvalidRequest) {
		t.Fatalf("非法排序字段错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 101}); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("limit 越界错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, err := env.service.ListPermissions(ctx, env.system, permission.ListRequest{
		Limit: 10, Offset: -1}); !errors.Is(err, permission.ErrInvalidRequest) {
		t.Fatalf("负 offset 错误 = %v，期望 ErrInvalidRequest", err)
	}
}
