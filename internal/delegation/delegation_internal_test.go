package delegation

import (
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// TestDataScopeSubsetRules 验证数据范围收缩规则：资源级上限不能转授未声明范围，
// 转授范围必须是上限子集；none 不转授数据所以总允许。
func TestDataScopeSubsetRules(t *testing.T) {
	parse := func(raw string) dataScope {
		scope, err := parseDataScope(raw)
		if err != nil {
			t.Fatalf("解析数据范围失败: %v", err)
		}
		return scope
	}
	all := dataScope{Mode: dataScopeAll}
	none := dataScope{Mode: dataScopeNone}
	undefined := parse("{}")
	resources12 := dataScope{Mode: dataScopeResources, Resources: []string{"r1", "r2"}}
	cases := []struct {
		name      string
		requested dataScope
		allowed   dataScope
		want      bool
	}{
		{"all 上限允许未声明", undefined, all, true},
		{"all 上限允许资源子集", resources12, all, true},
		{"资源上限拒绝未声明", undefined, resources12, false},
		{"资源上限拒绝 all", all, resources12, false},
		{"资源上限允许子集", dataScope{Mode: dataScopeResources, Resources: []string{"r1"}}, resources12, true},
		{"资源上限拒绝超集", dataScope{Mode: dataScopeResources, Resources: []string{"r1", "r3"}}, resources12, false},
		{"none 请求始终允许", none, resources12, true},
		{"none 上限只允许 none", resources12, none, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := dataScopeSubset(testCase.requested, testCase.allowed); got != testCase.want {
				t.Fatalf("dataScopeSubset(%+v, %+v) = %v，期望 %v",
					testCase.requested, testCase.allowed, got, testCase.want)
			}
		})
	}
}

// TestNormalizeMaxDataScope 验证委派上限只接受显式结构，未声明与非法结构拒绝。
func TestNormalizeMaxDataScope(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"空值默认 all", "", `{"v":1,"mode":"all"}`, false},
		{"all", `{"v":1,"mode":"all"}`, `{"v":1,"mode":"all"}`, false},
		{"none", `{"v":1,"mode":"none"}`, `{"v":1,"mode":"none"}`, false},
		{"resources 规范化排序", `{"v":1,"mode":"resources","resources":["r2","r1"]}`,
			`{"v":1,"mode":"resources","resources":["r1","r2"]}`, false},
		{"未声明拒绝", `{}`, "", true},
		{"未知版本拒绝", `{"v":2,"mode":"all"}`, "", true},
		{"未知字段拒绝", `{"v":1,"mode":"all","extra":1}`, "", true},
		{"空资源拒绝", `{"v":1,"mode":"resources","resources":[]}`, "", true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := normalizeMaxDataScope(testCase.input)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("期望错误，实际 = %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应失败: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("规范化结果 = %q，期望 %q", got, testCase.want)
			}
		})
	}
}

// TestAllowedTargetsJSONRoundTrip 验证目标白名单的规范编码与严格解析。
func TestAllowedTargetsJSONRoundTrip(t *testing.T) {
	targets := AllowedTargets{
		Users:  []string{"usr_22222222222222222222222222222222", "usr_11111111111111111111111111111111"},
		Groups: []string{"grp_11111111111111111111111111111111"},
	}
	encoded, err := targets.JSON()
	if err != nil {
		t.Fatalf("编码目标白名单失败: %v", err)
	}
	decoded, err := ParseAllowedTargetsJSON(encoded)
	if err != nil {
		t.Fatalf("解析目标白名单失败: %v", err)
	}
	if len(decoded.Users) != 2 || decoded.Users[0] >= decoded.Users[1] || len(decoded.Groups) != 1 {
		t.Fatalf("目标白名单往返结果 = %+v", decoded)
	}
	if !decoded.Restricted() {
		t.Fatal("非空白名单应标记为受限")
	}
	if _, err := ParseAllowedTargetsJSON(`{"v":1,"users":["bad"]}`); err == nil {
		t.Fatal("非法用户 ID 应被拒绝")
	}
	if _, err := ParseAllowedTargetsJSON(`{"v":1,"users":["usr_11111111111111111111111111111111","usr_11111111111111111111111111111111"]}`); err == nil {
		t.Fatal("重复目标应被拒绝")
	}
	if _, err := ParseAllowedTargetsJSON(`{"v":1,"unknown":1}`); err == nil {
		t.Fatal("未知字段应被拒绝")
	}
	if _, err := ParseAllowedTargetsJSON(""); err != nil {
		t.Fatalf("空白名单应表示不限制: %v", err)
	}
}

// TestGrantActiveAndIDs 验证委派资格有效期语义与稳定 ID 格式。
func TestGrantActiveAndIDs(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Minute)
	revokedAt := now.Add(-time.Minute)
	if !(Grant{}).Active(now) {
		t.Fatal("无有效期且未撤回的资格应有效")
	}
	if !(Grant{ExpiresAt: &expiry}).Active(now) {
		t.Fatal("有效期内资格应有效")
	}
	if (Grant{ExpiresAt: &expiry}).Active(expiry) {
		t.Fatal("到达有效期边界的资格应失效")
	}
	if (Grant{RevokedAt: &revokedAt}).Active(now) {
		t.Fatal("已撤回资格应失效")
	}
	id, err := NewGrantID(nil)
	if err != nil || !ValidGrantID(id) {
		t.Fatalf("生成资格 ID 失败: id=%q err=%v", id, err)
	}
	if ValidGrantID("dlg_bad") || ValidGrantID("") {
		t.Fatal("非法资格 ID 应被拒绝")
	}
	if trustedActor(actorOf("user")) || trustedActor(actorOf("anonymous")) {
		t.Fatal("普通用户/匿名不是受信通道")
	}
	if !trustedActor(actorOf("local_admin")) || !trustedActor(actorOf("system")) {
		t.Fatal("本地/系统应为受信通道")
	}
}

// TestTargetValidation 验证转授目标形状校验。
func TestTargetValidation(t *testing.T) {
	validUser := Target{Kind: TargetUser, ID: "usr_11111111111111111111111111111111"}
	if err := validUser.Valid(); err != nil {
		t.Fatalf("合法用户目标被拒绝: %v", err)
	}
	validGroup := Target{Kind: TargetGroup, ID: "grp_11111111111111111111111111111111"}
	if err := validGroup.Valid(); err != nil {
		t.Fatalf("合法用户组目标被拒绝: %v", err)
	}
	for _, target := range []Target{
		{Kind: TargetUser, ID: "bad"},
		{Kind: TargetGroup, ID: "usr_11111111111111111111111111111111"},
		{Kind: "tenant", ID: "usr_11111111111111111111111111111111"},
	} {
		if err := target.Valid(); err == nil {
			t.Fatalf("非法目标应被拒绝: %+v", target)
		}
	}
}

// actorOf 构造指定类型的审计身份，用于受信通道判断。
func actorOf(kind string) audit.Actor {
	return audit.Actor{Type: audit.ActorKind(kind)}
}
