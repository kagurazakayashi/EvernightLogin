package oauthflow_test

// 步骤 227：令牌状态查询在审计不可用时的行为证据。
//
// 现有设计：状态查询是只读在线查询，审计写入失败只记录告警，不把查询结果伪装成
// 失败，也不得泄露令牌原文/内部细节；成功与 inactive 两条路径都必须保持该语义。

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthclient"
	"github.com/kagurazakayashi/EvernightLogin/internal/oauthflow"
)

// auditDownRecorder 注入成功的 Record/RecordFailure 失败。
type auditDownRecorder struct {
	inner oauthflow.AuditRecorder
}

func (a auditDownRecorder) Record(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}

func (a auditDownRecorder) RecordFailure(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}

func (a auditDownRecorder) ExecuteCritical(ctx context.Context,
	request audit.CriticalRequest, change audit.Change) error {
	return a.inner.ExecuteCritical(ctx, request, change)
}

func TestInspectTokenAuditFailureIsVisibleNotFatal(t *testing.T) {
	env := newTestEnv(t, oauthclient.ClientTypePublic)
	env.enableRefreshClient()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	flow, err := oauthflow.New(oauthflow.Options{
		Store: env.flowStore, Audit: auditDownRecorder{inner: env.audit},
		Clients: env.source, ClientAuth: env.clientAuth, Sessions: env.session,
		Tokens: env.tokens, Reauth: env.reAuth, TokenVerifier: env.tokens,
		InspectAuthorizer: &inspectAuthorizer{allow: true},
		Now:               func() time.Time { return env.now }, Logger: logger,
	})
	if err != nil {
		t.Fatalf("构造审计失败的状态查询流程: %v", err)
	}
	first := env.exchangeWithRefresh()
	inspection, err := flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: first.AccessToken.Reveal(), Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_audit_1"})
	if err != nil {
		t.Fatalf("审计失败时只读查询不应失败: %v", err)
	}
	if !inspection.Active {
		t.Fatal("有效令牌在审计失败时仍应 active")
	}
	// inactive 路径同样不因审计失败改变协议结果。
	inactive, err := flow.InspectToken(env.ctx, oauthflow.TokenInspectRequest{
		Token: "not-a-real-token", Audience: testAudience,
		ResourceServerClientID: "app_000000000000000000000000000000aa",
		RequestID:              "req_inspect_audit_2"})
	if err != nil || inactive.Active {
		t.Fatalf("未知令牌 = %+v err=%v", inactive, err)
	}
	output := logs.String()
	if !strings.Contains(output, "令牌状态查询审计写入失败") {
		t.Fatalf("审计失败告警未记录: %s", output)
	}
	if strings.Contains(output, first.AccessToken.Reveal()) {
		t.Fatal("审计失败日志泄露了令牌原文")
	}
}
