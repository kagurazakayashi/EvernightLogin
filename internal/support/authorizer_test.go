package support_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	"github.com/kagurazakayashi/EvernightLogin/internal/support"
)

// fakeChecker 是 internal/authz.Service 的最小只读替身，用于验证生产适配器的
// 数据范围解释与目标保护判定（不访问数据库）。
type fakeChecker struct {
	checkResult  authz.CheckResult
	checkErr     error
	effective    authz.EffectiveResult
	effectiveErr error
}

func (f *fakeChecker) Check(ctx context.Context, caller authz.Caller, request authz.CheckRequest) (authz.CheckResult, error) {
	if f.checkErr != nil {
		return authz.CheckResult{}, f.checkErr
	}
	return f.checkResult, nil
}

func (f *fakeChecker) EffectivePermissions(ctx context.Context, caller authz.Caller, subjectUserID, scopeID string, options authz.ListOptions) (authz.EffectiveResult, error) {
	if f.effectiveErr != nil {
		return authz.EffectiveResult{}, f.effectiveErr
	}
	return f.effective, nil
}

// TestAuthzAuthorizerDataScope 验证生产授权适配器只接受 all/resources 数据范围，
// undefined/none 与未授予一律 fail-closed；客服资格同样 fail-closed。
func TestAuthzAuthorizerDataScope(t *testing.T) {
	const staffID = "usr_00000000000000000000000000000001"
	const targetID = "usr_00000000000000000000000000000011"
	cases := []struct {
		name      string
		decision  authz.PermissionDecision
		allowed   bool
		wantErr   bool
		wantAll   bool
		wantUsers []string
	}{
		{name: "all", decision: authz.PermissionDecision{Key: support.PermissionCasesRead, Allowed: true,
			DataScope: authz.DataScope{Mode: authz.DataScopeAll}}, allowed: true, wantAll: true},
		{name: "resources", decision: authz.PermissionDecision{Key: support.PermissionCasesRead, Allowed: true,
			DataScope: authz.DataScope{Mode: authz.DataScopeResources, Resources: []string{targetID}}},
			allowed: true, wantUsers: []string{targetID}},
		{name: "undefined", decision: authz.PermissionDecision{Key: support.PermissionCasesRead, Allowed: true,
			DataScope: authz.DataScope{Mode: authz.DataScopeUndefined}}, allowed: true, wantErr: true},
		{name: "none", decision: authz.PermissionDecision{Key: support.PermissionCasesRead, Allowed: true,
			DataScope: authz.DataScope{Mode: authz.DataScopeNone}}, allowed: true, wantErr: true},
		{name: "denied", decision: authz.PermissionDecision{Key: support.PermissionCasesRead}, allowed: false, wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			checker := &fakeChecker{checkResult: authz.CheckResult{
				Allowed:     testCase.allowed,
				Permissions: []authz.PermissionDecision{testCase.decision},
			}}
			authorizer, err := support.NewAuthzAuthorizer(checker)
			if err != nil {
				t.Fatalf("构造授权器: %v", err)
			}
			scope, err := authorizer.AuthorizeStaff(context.Background(), staffID, support.PermissionCasesRead)
			if testCase.wantErr {
				if !errors.Is(err, support.ErrAccessDenied) {
					t.Fatalf("错误 = %v，期望 ErrAccessDenied", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("授权失败: %v", err)
			}
			if scope.AllUsers != testCase.wantAll {
				t.Errorf("AllUsers = %v，期望 %v", scope.AllUsers, testCase.wantAll)
			}
			if !testCase.wantAll {
				if len(scope.UserIDs) != len(testCase.wantUsers) || !scope.Allows(targetID) {
					t.Errorf("数据范围 = %+v，期望包含 %v", scope, testCase.wantUsers)
				}
			}
		})
	}
	// 依赖故障按 AUTHZ_UNAVAILABLE fail-closed。
	broken, err := support.NewAuthzAuthorizer(&fakeChecker{checkErr: errors.New("数据库不可用")})
	if err != nil {
		t.Fatalf("构造授权器: %v", err)
	}
	if _, err := broken.AuthorizeStaff(context.Background(), staffID, support.PermissionCasesRead); !errors.Is(err, support.ErrAuthzUnavailable) {
		t.Fatalf("依赖故障错误 = %v，期望 ErrAuthzUnavailable", err)
	}
	// 空 checker 拒绝构造（fail-closed）。
	if _, err := support.NewAuthzAuthorizer(nil); !errors.Is(err, support.ErrOptionsInvalid) {
		t.Fatalf("空 checker 构造错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 客服资格：允许/拒绝/故障均 fail-closed。
	eligible := &fakeChecker{checkResult: authz.CheckResult{Allowed: true,
		Permissions: []authz.PermissionDecision{{Key: support.PermissionCasesRead, Allowed: true,
			DataScope: authz.DataScope{Mode: authz.DataScopeAll}}}}}
	authorizer, err := support.NewAuthzAuthorizer(eligible)
	if err != nil {
		t.Fatalf("构造授权器: %v", err)
	}
	if ok, err := authorizer.StaffEligible(context.Background(), staffID); err != nil || !ok {
		t.Fatalf("客服资格 = %v %v，期望允许", ok, err)
	}
}

// TestAuthzTargetProtector 验证高权限目标识别：持有受保护权限、root/被拒、结果被
// 截断或依赖故障时都按受保护 fail-closed。
func TestAuthzTargetProtector(t *testing.T) {
	const targetID = "usr_00000000000000000000000000000011"
	cases := []struct {
		name      string
		effective authz.EffectiveResult
		want      bool
	}{
		{name: "普通用户", effective: authz.EffectiveResult{SubjectUserID: targetID}, want: false},
		{name: "持有管理权限", effective: authz.EffectiveResult{SubjectUserID: targetID,
			Permissions: []authz.EffectivePermission{{Key: "users.update"}}}, want: true},
		{name: "root或停用被拒", effective: authz.EffectiveResult{DeniedCode: authz.CodeAccessDenied}, want: true},
		{name: "结果被截断", effective: authz.EffectiveResult{SubjectUserID: targetID, HasMore: true}, want: true},
		{name: "来源截断", effective: authz.EffectiveResult{SubjectUserID: targetID, SourceLimitReached: true}, want: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			protector, err := support.NewAuthzTargetProtector(&fakeChecker{effective: testCase.effective})
			if err != nil {
				t.Fatalf("构造目标识别器: %v", err)
			}
			protected, err := protector.Protected(context.Background(), targetID)
			if err != nil {
				t.Fatalf("识别目标: %v", err)
			}
			if protected != testCase.want {
				t.Errorf("Protected = %v，期望 %v", protected, testCase.want)
			}
		})
	}
	// 依赖故障返回错误，由服务 fail-closed 映射为 AUTHZ_UNAVAILABLE。
	broken, err := support.NewAuthzTargetProtector(&fakeChecker{effectiveErr: errors.New("权限服务不可用")})
	if err != nil {
		t.Fatalf("构造目标识别器: %v", err)
	}
	if _, err := broken.Protected(context.Background(), targetID); !errors.Is(err, support.ErrAuthzUnavailable) {
		t.Fatalf("依赖故障错误 = %v，期望 ErrAuthzUnavailable", err)
	}
}
