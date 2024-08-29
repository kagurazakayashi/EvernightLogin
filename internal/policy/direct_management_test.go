package policy_test

import (
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/policy"
)

// TestDirectManagementOperationsRegistered 验收“注册直接改名与重置密码的独立权限”
// 在敏感操作注册表侧的定义：两条操作各自绑定独立权限键、默认要求操作者本次两步
// 验证，并启用不可降级安全下限；业务执行入口未落地前不能标记为已实现。
func TestDirectManagementOperationsRegistered(t *testing.T) {
	catalog := policy.DefaultCatalog()
	if err := catalog.Validate(); err != nil {
		t.Fatalf("默认敏感操作目录不合法: %v", err)
	}
	cases := []struct {
		operationID   string
		permissionKey string
		domain        policy.Domain
	}{
		{policy.OperationDirectUsernameChange, "users.username.change.other", policy.DomainProfile},
		{policy.OperationDirectPasswordReset, "users.password.reset.other", policy.DomainPassword},
	}
	seen := make(map[string]struct{}, len(cases))
	for _, item := range cases {
		operation, found := catalog.Lookup(item.operationID)
		if !found {
			t.Fatalf("敏感操作目录缺少 %q", item.operationID)
		}
		if operation.PermissionKey != item.permissionKey {
			t.Fatalf("操作 %q 的权限键 = %q，期望 %q", item.operationID, operation.PermissionKey, item.permissionKey)
		}
		if operation.Domain != item.domain {
			t.Fatalf("操作 %q 的业务域 = %q，期望 %q", item.operationID, operation.Domain, item.domain)
		}
		// 两条操作不是 root_only 权限：持专门权限的非 root 操作者也可执行，但业务
		// 侧仍拒绝受保护目标；root 依靠既有全权限语义而不是普通角色分配拥有它们。
		if operation.RootOnly {
			t.Fatalf("操作 %q 不应是 root_only（非 root 管理员可凭专门权限执行）", item.operationID)
		}
		if !operation.ImmutableSensitive || !operation.ImmutableMinimum {
			t.Fatalf("操作 %q 必须启用敏感标记与不可降级下限保护: %+v", item.operationID, operation)
		}
		if operation.MinimumStrength != policy.StrengthStrong {
			t.Fatalf("操作 %q 的最低认证强度 = %q，期望 strong", item.operationID, operation.MinimumStrength)
		}
		if operation.Implemented {
			t.Fatalf("操作 %q 的业务入口尚未落地，不能标记为已实现", item.operationID)
		}
		want := policy.Policy{Sensitive: true, ReauthRequired: true, MaxAuthAgeSeconds: 300,
			Strength: policy.StrengthStrong, ConfirmationRequired: true, NotificationRequired: true}
		if !operation.Default.Equal(want) {
			t.Fatalf("操作 %q 默认策略 = %+v，期望 %+v", item.operationID, operation.Default, want)
		}
		if _, duplicated := seen[operation.PermissionKey]; duplicated {
			t.Fatalf("权限键 %q 被重复用于多条操作", operation.PermissionKey)
		}
		seen[operation.PermissionKey] = struct{}{}
	}
}

// TestDirectManagementMinimumCannotBeLowered 验收“不可降为单因素的下限”：root 的
// 策略覆盖必须被拒绝，且拒绝不留存储行；允许加严与调整告知。
func TestDirectManagementMinimumCannotBeLowered(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	ctx := env.ctx

	invalid := []struct {
		name   string
		change policy.PolicyChange
	}{
		{name: "取消再次验证并降为单因素", change: policy.PolicyChange{
			ReauthRequired:    boolPtr(false),
			MaxAuthAgeSeconds: intPtr(0),
			RequiredStrength:  strengthPtr(policy.StrengthNone),
		}},
		{name: "保留再次验证但降为密码单因素", change: policy.PolicyChange{
			RequiredStrength: strengthPtr(policy.StrengthPassword),
		}},
		{name: "放宽认证新鲜度", change: policy.PolicyChange{
			MaxAuthAgeSeconds: intPtr(3600),
		}},
		{name: "取消敏感标记", change: clearToNonSensitive()},
	}
	for _, operationID := range []string{policy.OperationDirectUsernameChange, policy.OperationDirectPasswordReset} {
		for _, test := range invalid {
			t.Run(operationID+"/"+test.name, func(t *testing.T) {
				_, err := env.service.Set(ctx, root, policy.SetRequest{
					ScopeID: "system", OperationID: operationID,
					Change: test.change, ExpectedVersion: 0, RequestID: "req-direct-minimum",
				})
				if !errors.Is(err, policy.ErrInvalidChange) {
					t.Fatalf("降级覆盖错误 = %v，期望 ErrInvalidChange", err)
				}
			})
		}
	}
	if rows := env.count(`SELECT COUNT(*) FROM sensitive_operation_policies`); rows != 0 {
		t.Fatalf("被拒绝的降级覆盖写入了 %d 行，期望 0", rows)
	}
	if version, err := env.service.Version(ctx, root, "system"); err != nil || version != 0 {
		t.Fatalf("被拒绝后策略版本 = (%d, %v)，期望 0", version, err)
	}

	// 加严与调整告知仍然允许：更短的新鲜度 + 关闭告知 + 关闭额外确认。
	tightened, err := env.service.Set(ctx, root, policy.SetRequest{
		ScopeID: "system", OperationID: policy.OperationDirectUsernameChange,
		Change: policy.PolicyChange{
			MaxAuthAgeSeconds:    intPtr(120),
			ConfirmationRequired: boolPtr(false),
			NotificationRequired: boolPtr(false),
		},
		ExpectedVersion: 0, RequestID: "req-direct-minimum-tighten",
	})
	if err != nil {
		t.Fatalf("加严覆盖被错误拒绝: %v", err)
	}
	operation, found := tightened.Lookup(policy.OperationDirectUsernameChange)
	if !found {
		t.Fatal("加严后快照缺少操作")
	}
	if !operation.Effective.ReauthRequired || operation.Effective.Strength != policy.StrengthStrong ||
		operation.Effective.MaxAuthAgeSeconds != 120 || operation.Effective.ConfirmationRequired ||
		operation.Effective.NotificationRequired {
		t.Fatalf("加严后有效策略 = %+v，期望保持两步验证下限且使用更短新鲜度", operation.Effective)
	}
}

// TestDirectManagementMinimumReadFallback 验收读取兜底：历史数据或外部写入的违规
// 覆盖行即使绕过 Set 校验也生效不了，有效策略会被提升到安全下限。
func TestDirectManagementMinimumReadFallback(t *testing.T) {
	env := newTestEnv(t, nil)
	env.seedUser(rootUserID, "root", true)
	root := env.rootCaller()
	ctx := env.ctx

	now := testRecordTime.UnixMilli()
	if _, err := env.storage.DB().ExecContext(ctx, `INSERT INTO sensitive_operation_policies(
scope_id,operation_id,is_sensitive,reauth_required,max_auth_age_seconds,required_strength,
confirmation_required,notification_required,source_kind,name,description,row_version,
created_at_ms,updated_at_ms
) VALUES('system',?,1,0,0,'password',0,0,'override','','',1,?,?)`,
		policy.OperationDirectPasswordReset, now, now); err != nil {
		t.Fatalf("写入违规覆盖失败: %v", err)
	}
	snapshot, err := env.service.Effective(ctx, root, "system")
	if err != nil {
		t.Fatalf("读取有效策略失败: %v", err)
	}
	operation, found := snapshot.Lookup(policy.OperationDirectPasswordReset)
	if !found {
		t.Fatal("快照缺少直接重置密码操作")
	}
	if operation.Source != policy.SourceOverride || operation.Override == nil {
		t.Fatalf("兜底来源异常: %+v", operation)
	}
	// 存储里的违规值保持可见（便于审计/修复），但实际生效策略必须满足下限。
	if operation.Override.ReauthRequired || operation.Override.Strength != policy.StrengthPassword {
		t.Fatalf("覆盖行快照 = %+v，期望保留原始存储值供审计", operation.Override)
	}
	effective := operation.Effective
	if !effective.Sensitive || !effective.ReauthRequired || effective.Strength != policy.StrengthStrong {
		t.Fatalf("读取兜底后有效策略 = %+v，期望敏感 + 再次验证 + strong", effective)
	}
	if effective.MaxAuthAgeSeconds != 300 {
		t.Fatalf("读取兜底后新鲜度 = %d，期望回落到目录默认 300", effective.MaxAuthAgeSeconds)
	}
}
