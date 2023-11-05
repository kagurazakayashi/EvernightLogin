package main

// 步骤 220：分页审计（可增长列表识别、证据成对、跨入口契约一致）的负向/正向
// 单元测试。测试只使用内存构造的盘点结构或本仓库真实源码，不启动服务、不联网。

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestClassifyAppListSymbol 覆盖请求/结果类型识别与边界字段判定。
func TestClassifyAppListSymbol(t *testing.T) {
	cases := []struct {
		name      string
		symbol    *appSymbol
		wantKind  string
		wantBound bool
		wantCont  string
	}{
		{
			name: "列表结果",
			symbol: &appSymbol{Name: "AdminUserList", Kind: "struct",
				FieldTypes: map[string]string{"Users": "[]AdminUser", "HasMore": "bool",
					"Page": "AdminPageInfo"}},
			wantKind: "result", wantBound: true, wantCont: "HasMore,Page",
		},
		{
			name: "列表请求",
			symbol: &appSymbol{Name: "AdminListUsersRequest", Kind: "struct",
				FieldTypes: map[string]string{"Page": "AdminPage", "Caller": "AdminCaller"}},
			wantKind: "request", wantBound: true,
		},
		{
			name: "旧式 Limit/Offset 请求",
			symbol: &appSymbol{Name: "AdminPermissionQuery", Kind: "struct",
				FieldTypes: map[string]string{"Limit": "int", "Offset": "int"}},
			wantKind: "request", wantBound: true,
		},
		{
			name: "缺少继续字段的结果",
			symbol: &appSymbol{Name: "ThingList", Kind: "struct",
				FieldTypes: map[string]string{"Items": "[]Thing"}},
			wantKind: "result", wantBound: false,
		},
		{
			name: "非列表结构",
			symbol: &appSymbol{Name: "AdminUser", Kind: "struct",
				FieldTypes: map[string]string{"ID": "string"}},
		},
		{
			name: "枚举视图不以 List 结尾",
			symbol: &appSymbol{Name: "AdminSessionView", Kind: "struct",
				FieldTypes: map[string]string{"ID": "string"}},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			kind, bounded, _, continuation := classifyAppListSymbol(test.symbol.Name, test.symbol)
			if kind != test.wantKind || bounded != test.wantBound {
				t.Fatalf("kind=%q bounded=%v，期望 %q/%v", kind, bounded, test.wantKind, test.wantBound)
			}
			if test.wantCont != "" && strings.Join(continuation, ",") != test.wantCont {
				t.Fatalf("继续字段 = %v，期望 %s", continuation, test.wantCont)
			}
		})
	}
}

// TestPaginationEvidenceProblem 覆盖证据成对校验：缺少请求/继续证据、
// continuation=gap 的显式例外必须写理由、fixed/none 必须有理由。
func TestPaginationEvidenceProblem(t *testing.T) {
	inv := &inventory{AppTypes: map[string]*appSymbol{
		"AdminUserList": {Name: "AdminUserList", Kind: "struct",
			FieldTypes: map[string]string{"Users": "[]AdminUser", "HasMore": "bool"}},
		"AdminListUsersRequest": {Name: "AdminListUsersRequest", Kind: "struct",
			FieldTypes: map[string]string{"Limit": "int", "Offset": "int"}},
		"SessionDeviceList": {Name: "SessionDeviceList", Kind: "struct",
			FieldTypes: map[string]string{"Devices": "[]SessionDevice", "Page": "AdminPageInfo"}},
	}}
	cases := []struct {
		name  string
		claim *paginationClaim
		want  string
	}{
		{"成对证据通过", &paginationClaim{Mode: paginationModeOffset,
			Evidence: []string{"AdminListUsersRequest.Limit", "AdminListUsersRequest.Offset", "AdminUserList.HasMore"}}, ""},
		{"只有请求证据", &paginationClaim{Mode: paginationModeOffset,
			Evidence: []string{"AdminListUsersRequest.Limit"}}, "缺少结果继续证据"},
		{"只有继续证据", &paginationClaim{Mode: paginationModeOffset,
			Evidence: []string{"AdminUserList.HasMore"}}, "缺少请求分页边界证据"},
		{"内部 token 成对", &paginationClaim{Mode: paginationModeOffset,
			Evidence: []string{"internal/session/service.go:Limit", "internal/session/service.go:HasMore"}}, ""},
		{"gap 例外无理由", &paginationClaim{Mode: paginationModeOffset, Continuation: continuationGap,
			Evidence: []string{"AdminListUsersRequest.Limit"}}, "必须写明理由"},
		{"gap 例外有理由", &paginationClaim{Mode: paginationModeOffset, Continuation: continuationGap,
			Reason: "仅单页上限，无继续语义", Evidence: []string{"AdminListUsersRequest.Limit"}}, ""},
		{"未知 continuation", &paginationClaim{Mode: paginationModeOffset,
			Continuation: "bogus", Evidence: []string{"AdminListUsersRequest.Limit", "AdminUserList.HasMore"}}, "未知 continuation"},
		{"fixed 无理由", &paginationClaim{Mode: paginationModeFixed}, "必须写明理由"},
		{"fixed 有理由", &paginationClaim{Mode: paginationModeFixed, Reason: "固定少量枚举"}, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			problem := paginationEvidenceProblem(inv, test.claim)
			if test.want == "" && problem != "" {
				t.Fatalf("期望通过，实际: %s", problem)
			}
			if test.want != "" && !strings.Contains(problem, test.want) {
				t.Fatalf("问题 = %q，期望包含 %q", problem, test.want)
			}
		})
	}
}

// TestContractMismatches 覆盖跨入口默认值/上限/页面参数不一致检测。
func TestContractMismatches(t *testing.T) {
	consistent := paginationContract{AppDefaultLimit: 20, AppMaxLimit: 100, AppMaxOffset: 1000000,
		SessionDefaultLimit: 20, SessionMaxLimit: 100, AuthzDefaultLimit: 20, AuthzMaxLimit: 100,
		CLIDefaultLimit: 20, CLIMaxLimit: 100, CLIOffsetCap: 1000000,
		PageOffsetCap: 1000000, PageFixedLimit: 20}
	if mismatches := contractMismatches(consistent); len(mismatches) != 0 {
		t.Fatalf("一致契约不应有不一致: %v", mismatches)
	}
	cases := []struct {
		name   string
		mutate func(*paginationContract)
		want   string
	}{
		{"app 值缺失", func(c *paginationContract) { c.AppDefaultLimit = 0 }, "无法解析"},
		{"session 默认值不一致", func(c *paginationContract) { c.SessionDefaultLimit = 10 }, "session 默认页大小"},
		{"authz 最大值不一致", func(c *paginationContract) { c.AuthzMaxLimit = 50 }, "authz 最大列表上限"},
		{"CLI 上限不一致", func(c *paginationContract) { c.CLIDefaultLimit = 10 }, "CLI 默认页大小"},
		{"CLI offset 不一致", func(c *paginationContract) { c.CLIOffsetCap = 100 }, "CLI offset 上限"},
		{"页面 offset 不一致", func(c *paginationContract) { c.PageOffsetCap = 100 }, "页面 offset 上限"},
		{"页面固定页大小不一致", func(c *paginationContract) { c.PageFixedLimit = 50 }, "页面固定页大小"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			contract := consistent
			test.mutate(&contract)
			mismatches := contractMismatches(contract)
			if len(mismatches) == 0 {
				t.Fatalf("期望检测到不一致")
			}
			found := false
			for _, mismatch := range mismatches {
				if strings.Contains(mismatch, test.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("不一致项 = %v，期望包含 %q", mismatches, test.want)
			}
		})
	}
}

// TestRepoPaginationAuditRealSource 用本仓库真实源码运行一次分页审计：跨入口参数
// 必须一致，且能识别出有界可增长列表（防止盘点规则退化为空）。
func TestRepoPaginationAuditRealSource(t *testing.T) {
	root := filepath.Join("..", "..")
	contract := scanPaginationContract(root)
	if contract.AppDefaultLimit != 20 || contract.AppMaxLimit != 100 ||
		contract.AppMaxOffset != 1000000 {
		t.Fatalf("app 分页契约解析异常: %+v", contract)
	}
	if mismatches := contractMismatches(contract); len(mismatches) != 0 {
		t.Fatalf("真实仓库跨入口分页参数不一致: %v", mismatches)
	}
	catalog, err := loadCatalog(filepath.Join(root, "scripts", "capabilities", "catalog.json"))
	if err != nil {
		t.Fatalf("loadCatalog: %v", err)
	}
	inv, _, err := scanRepo(root)
	if err != nil {
		t.Fatalf("scanRepo: %v", err)
	}
	audit := buildPaginationAudit(root, catalog, inv)
	if len(audit.GrowableLists) < 10 {
		t.Fatalf("可增长列表盘点过少: %d", len(audit.GrowableLists))
	}
	if audit.BoundedLists == 0 {
		t.Fatal("未识别到任何有界列表")
	}
	if len(audit.ContractMismatches) != 0 {
		t.Fatalf("分页审计契约不一致: %v", audit.ContractMismatches)
	}
	// 已知 216/217 的公开分页列表应被识别并关联能力声明。
	foundAdminList := false
	for _, list := range audit.GrowableLists {
		if list.Name == "AdminPageInfo" || list.Name == "AdminGroupList" {
			foundAdminList = true
		}
	}
	if !foundAdminList {
		t.Fatalf("未识别到 216/217 分页类型: %+v", audit.GrowableLists)
	}
}
