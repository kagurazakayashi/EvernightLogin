package serverapp

// 步骤 146：托管策略一次性批准器的单元测试。真实 managedapi/SQLite 的策略
// 行版本/审计由 internal/managedapi 与迁移测试覆盖；这里验证页面与 managedapi
// 之间最关键的绑定语义：request_id + 主体 + 应用 + 行版本 + 策略摘要，单次消费。

import (
	"context"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/reauth"
)

func TestManagedPolicyApprovalsOneTimeBinding(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	g := newManagedPolicyApprovals(func() time.Time { return now })
	binding := login.UIAppPolicyActionBinding{
		ApplicationID:      "app_11111111111111111111111111111111",
		ExpectedRowVersion: 4, PolicyDigest: "digest-one", RequestID: "req_146_approval",
	}
	if err := g.Register("usr_root", binding); err != nil {
		t.Fatalf("登记批准失败: %v", err)
	}
	caller, err := reauth.UserCaller("usr_root")
	if err != nil {
		t.Fatalf("构造 caller: %v", err)
	}
	request := reauth.Request{OperationID: "managed_api.policy.manage",
		TargetType: "application", TargetID: binding.ApplicationID,
		Params: map[string]string{
			"application_id":       binding.ApplicationID,
			"expected_row_version": "4",
			"reauth_binding":       binding.PolicyDigest,
		}, RequestID: binding.RequestID}
	result, err := g.Authorize(context.Background(), caller, request)
	if err != nil || result.Method != "approval" || result.RequestID != binding.RequestID {
		t.Fatalf("匹配批准应通过: result=%+v err=%v", result, err)
	}
	if _, err := g.Authorize(context.Background(), caller, request); err == nil {
		t.Fatal("批准必须单次消费，第二次应拒绝")
	}
}

func TestManagedPolicyApprovalsRejectsMismatch(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*reauth.Request)
	}{
		{"different digest", func(request *reauth.Request) { request.Params["reauth_binding"] = "digest-two" }},
		{"different version", func(request *reauth.Request) { request.Params["expected_row_version"] = "5" }},
		{"different app", func(request *reauth.Request) {
			request.TargetID = "app_22222222222222222222222222222222"
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			g := newManagedPolicyApprovals(func() time.Time { return now })
			binding := login.UIAppPolicyActionBinding{
				ApplicationID:      "app_11111111111111111111111111111111",
				ExpectedRowVersion: 4, PolicyDigest: "digest-one", RequestID: "req_146_mismatch",
			}
			if err := g.Register("usr_root", binding); err != nil {
				t.Fatalf("登记批准失败: %v", err)
			}
			caller, _ := reauth.UserCaller("usr_root")
			request := reauth.Request{OperationID: "managed_api.policy.manage",
				TargetType: "application", TargetID: binding.ApplicationID,
				Params: map[string]string{
					"application_id":       binding.ApplicationID,
					"expected_row_version": "4",
					"reauth_binding":       binding.PolicyDigest,
				}, RequestID: binding.RequestID}
			testCase.mutate(&request)
			if _, err := g.Authorize(context.Background(), caller, request); err == nil {
				t.Fatal("不匹配的批准参数必须拒绝")
			}
		})
	}
	// 主体不匹配：使用同一 request_id 的另一个用户不能消费。
	g := newManagedPolicyApprovals(func() time.Time { return now })
	binding := login.UIAppPolicyActionBinding{ApplicationID: "app_11111111111111111111111111111111",
		ExpectedRowVersion: 4, PolicyDigest: "digest-one", RequestID: "req_146_subject"}
	if err := g.Register("usr_root", binding); err != nil {
		t.Fatalf("登记批准失败: %v", err)
	}
	other, _ := reauth.UserCaller("usr_other")
	request := reauth.Request{OperationID: "managed_api.policy.manage",
		TargetType: "application", TargetID: binding.ApplicationID,
		Params:    map[string]string{"expected_row_version": "4", "reauth_binding": "digest-one"},
		RequestID: binding.RequestID}
	if _, err := g.Authorize(context.Background(), other, request); err == nil {
		t.Fatal("不同主体不能消费批准")
	}
}

func TestManagedPolicyApprovalsExpiry(t *testing.T) {
	now := time.Date(2026, 11, 21, 20, 0, 0, 0, time.UTC)
	g := newManagedPolicyApprovals(func() time.Time { return now })
	binding := login.UIAppPolicyActionBinding{ApplicationID: "app_11111111111111111111111111111111",
		ExpectedRowVersion: 1, PolicyDigest: "digest", RequestID: "req_146_expiry"}
	if err := g.Register("usr_root", binding); err != nil {
		t.Fatalf("登记批准失败: %v", err)
	}
	now = now.Add(31 * time.Second)
	caller, _ := reauth.UserCaller("usr_root")
	request := reauth.Request{OperationID: "managed_api.policy.manage",
		TargetType: "application", TargetID: binding.ApplicationID,
		Params:    map[string]string{"expected_row_version": "1", "reauth_binding": "digest"},
		RequestID: binding.RequestID}
	if _, err := g.Authorize(context.Background(), caller, request); err == nil {
		t.Fatal("过期批准必须拒绝")
	}
	if _, err := g.Authorize(context.Background(), caller, request); err == nil {
		t.Fatal("过期批准不得因未清理而被复用")
	}
}

func TestManagedPolicyAuthorizerReaderIsSystemOnly(t *testing.T) {
	authorizer := managedPolicyAuthorizer{}
	if err := authorizer.AuthorizePolicy(context.Background(),
		audit.Actor{Type: audit.ActorSystem, ID: managedPolicyReaderID}, ""); err != nil {
		t.Fatalf("受信页面只读通道应允许: %v", err)
	}
	for _, actor := range []audit.Actor{
		{Type: audit.ActorSystem, ID: "system"},
		{Type: audit.ActorUser, ID: "usr_regular"},
		{Type: audit.ActorAnonymous, ID: ""},
	} {
		if err := authorizer.AuthorizePolicy(context.Background(), actor, ""); err == nil {
			t.Fatalf("非受信策略通道主体 %+v 必须拒绝", actor)
		}
	}
}
